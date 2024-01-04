import json
from pathlib import Path
from pprint import pformat
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode

import oauthlib
from jinja2 import ChoiceLoader, FileSystemLoader
from jupyterhub.handlers import BaseHandler  # type: ignore
from tornado import gen

from ..utils import convert_request_to_dict, get_browser_protocol
from .templates import LTI11_CONFIG_TEMPLATE

TEMPLATE_DIR = str(Path(__file__).parent.parent / 'templates')


def ensure_template_path(handler: BaseHandler):
    """ Adds our template path to the Jinja2 search path. """

    if getattr(ensure_template_path, 'called', False):
        return

    handler.log.info('Adding %s to template path', TEMPLATE_DIR)
    loader = FileSystemLoader([TEMPLATE_DIR])

    env = handler.settings['jinja2_env']
    previous_loader = env.loader
    env.loader = ChoiceLoader([previous_loader, loader])

    ensure_template_path.called = True


class LTI11AuthenticateHandler(BaseHandler):
    """
    Implements v1.1 of the LTI protocol for passing authentication information
    through.

    If there's a custom parameter called 'next', will redirect user to
    that URL after authentication. Else, will send them to /home.
    """

    def set_login_cookie(self, user):
        super().set_login_cookie(user)

        # Make sure that hub cookie is always set, even if the user was already logged in
        self.set_hub_cookie(user)

    def check_xsrf_cookie(self):
        """
        Do not attempt to check for xsrf parameter in POST requests. LTI requests are
        meant to be cross-site, so it must not be verified.
        """
        return

    @gen.coroutine
    def get(self):
        self.log.info("Showing the login page.....")
        html = yield self.render_template(
            "templates/page.html",
            announcement="Please log in via your LMS."
        )
        self.finish(html)

    @gen.coroutine
    def post(self):
        """
        Technical reference of relevance to understand this function
        ------------------------------------------------------------
        1. Class dependencies
           - jupyterhub.handlers.BaseHandler: https://github.com/jupyterhub/jupyterhub/blob/abb93ad799865a4b27f677e126ab917241e1af72/jupyterhub/handlers/base.py#L69
           - tornado.web.RequestHandler: https://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler
        2. Function dependencies
           - login_user: https://github.com/jupyterhub/jupyterhub/blob/abb93ad799865a4b27f677e126ab917241e1af72/jupyterhub/handlers/base.py#L696-L715
             login_user is defined in the JupyterHub wide BaseHandler class,
             mainly wraps a call to the authenticate function and follow up.
             a successful authentication with a call to auth_to_user that
             persists a JupyterHub user and returns it.
           - get_next_url: https://github.com/jupyterhub/jupyterhub/blob/abb93ad799865a4b27f677e126ab917241e1af72/jupyterhub/handlers/base.py#L587
           - get_body_argument: https://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler.get_body_argument
        """

        try:
            lti_message_type = self.request.arguments['lti_message_type'][0]
        except (KeyError, IndexError):
            self.log.warn("No lti_message_type argument found")
            lti_message_type = b''

        if lti_message_type == b"ContentItemSelectionRequest":
            yield self.show_content_item_selection()
            return

        # FIXME: Figure out if we want to pass the user returned from
        #        self.login_user() to self.get_next_url(). It is named
        #        _ for now as pyflakes is fine about having an unused
        #        variable named _.
        _ = yield self.login_user()
        next_url = self.get_next_url()
        body_argument = self.get_body_argument(
            name="custom_next",
            default=next_url,
        )

        self.redirect(body_argument)

    @gen.coroutine
    def show_content_item_selection(self):
        self.log.info("LTI11AuthenticateHandler.show_content_item_selection()")
        ensure_template_path(self)

        # For the simple link without nbgitpuller, create a form that we just have to POST
        content_items = {
            "@context": "http://purl.imsglobal.org/ctx/lti/v1/ContentItem",
            "@graph": [
                {
                    "mediaType": "application/vnd.ims.lti.v1.ltilink",
                    "@type": "LtiLinkItem",
                    "title": "Sample LTI launch",
                    "text": "<p>A sample LTI link created using the Content-Item message.</p>",
                }
            ]
        }

        response = {
            'content_items': json.dumps(content_items),
            "lti_message_type": "ContentItemSelection",
            "lti_version": "LTI-1p0",
            "data": "Some opaque TC data",
            "oauth_callback": "about:blank",
        }

        # extract the request arguments to a dict
        args = convert_request_to_dict(self.request.arguments)
        self.log.info("Decoded args from request: %s" % args)

        return_url = args["content_item_return_url"]
        oauth_consumer_key = args["oauth_consumer_key"]
        oauth_consumer_secret = self.authenticator.consumers[oauth_consumer_key]
        signed_response = sign_params_for_form(
            response, return_url, oauth_consumer_key, oauth_consumer_secret)

        # Display the select_link.html template
        html = yield self.render_template(
            "select_link.html",
            # For the simple link
            return_url=return_url,
            response_params=signed_response,
            # For informing the user
            tool_consumer_instance_name=args["tool_consumer_instance_name"],
            # For debugging
            lti_vars_str=pformat(args),
            # For the second step
            content_item_return_url=args["content_item_return_url"],
            oauth_consumer_key=args["oauth_consumer_key"],
        )

        self.finish(html)


class LTI11CreateLinkHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        self.log.info("LTI11CreateLinkHandler.post()")

        # extract the request arguments to a dict
        args = convert_request_to_dict(self.request.arguments)
        self.log.info("Decoded args from request: %s" % args)

        ensure_template_path(self)

        oauth_consumer_key = args["oauth_consumer_key"]
        oauth_consumer_secret = self.authenticator.consumers[oauth_consumer_key]

        repo = args['repo']
        branch = args['branch']
        urlpath = args['urlpath']
        nbgitpuller_link = "/hub/user-redirect/git-pull?" + \
            urlencode({"repo": repo, "urlpath": urlpath, "branch": branch})

        content_items = {
            "@context": "http://purl.imsglobal.org/ctx/lti/v1/ContentItem",
            "@graph": [
                {
                    "mediaType": "application/vnd.ims.lti.v1.ltilink",
                    "@type": "LtiLinkItem",
                    "title": "NBGitPuller launch",
                    "text": f'<p>Open <a href="{repo}">{repo}</a> in JupyterHub</p>',
                    "custom": {
                        "next": nbgitpuller_link,
                    }
                }
            ]
        }

        response = {
            'content_items': json.dumps(content_items),
            "lti_message_type": "ContentItemSelection",
            "lti_version": "LTI-1p0",
            "data": "Some opaque TC data",
            "oauth_callback": "about:blank",
        }

        return_url = args["content_item_return_url"]
        signed_response = sign_params_for_form(
            response, return_url, oauth_consumer_key, oauth_consumer_secret)

        self.log.info("response: %s" % pformat(response))
        self.log.info("signed_response: %s" % pformat(signed_response))

        html = yield self.render_template(
            "create_link.html",
            lti_vars_str=pformat(args),
            return_url=return_url,
            response_params=signed_response,
        )
        self.finish(html)


def sign_params_for_form(parameters: Dict[str, str], return_url: str, oauth_key: str, oauth_secret: str) -> List[Tuple[str, str]]:
    """ Sign some parameters with OAuth in a way that they can be posted by a form. """

    cli = oauthlib.oauth1.Client(
        oauth_key, oauth_secret,
        signature_type=oauthlib.oauth1.SIGNATURE_TYPE_BODY)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    form_body = urlencode(parameters)

    _, _, body = cli.sign(return_url, http_method="POST",
                          body=form_body, headers=headers)
    params_plus_sig = parse_qsl(body)
    return params_plus_sig


class LTI11ConfigHandler(BaseHandler):
    """
    Renders LTI 1.1 configuration file in XML format. Having the external tool's
    settings available with a configuration URL with the standard LTI 1.1 XML format
    allows users to use the URL and/or Paste XML options when defining the external
    tool settings within a a tool consumer, such as a Learning Management System (LMS).

    This configuration option is also known as Defining an LTI Link for a Tool Consumer.

    ref: http://www.imsglobal.org/specs/lti/xml
    """

    def get(self) -> None:
        """
        Renders the XML config which is used by LTI consumers to install the external tool.
        """
        self.set_header("Content-Type", "application/xml")

        # get the launch url from the client request
        protocol = self.authenticator.get_uri_scheme(self.request)
        launch_url = f"{protocol}://{self.request.host}{self.application.settings['base_url']}hub/lti/launch"
        self.log.debug(f"Calculated launch URL is: {launch_url}")

        # build the configuration XML
        config_xml = LTI11_CONFIG_TEMPLATE.format(
            description=self.authenticator.config_description,
            icon=self.authenticator.config_icon,
            launch_url=launch_url,
            title=self.authenticator.config_title,
        )

        self.write(config_xml)
