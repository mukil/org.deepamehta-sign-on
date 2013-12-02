package org.deepamehta.plugins.signon;

import com.sun.jersey.api.view.Viewable;
import de.deepamehta.core.Topic;
import de.deepamehta.core.RelatedTopic;
import de.deepamehta.core.model.CompositeValueModel;
import de.deepamehta.core.model.SimpleValue;
import de.deepamehta.core.model.TopicModel;
import de.deepamehta.core.service.ClientState;
import de.deepamehta.core.service.event.AllPluginsActiveListener;
import de.deepamehta.core.service.PluginService;
import de.deepamehta.core.service.annotation.ConsumesService;
import de.deepamehta.core.storage.spi.DeepaMehtaTransaction;
import de.deepamehta.core.util.JavaUtils;
import de.deepamehta.plugins.accesscontrol.model.Credentials;
import de.deepamehta.plugins.accesscontrol.service.AccessControlService;
import de.deepamehta.plugins.webactivator.WebActivatorPlugin;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Set;
import java.util.logging.Level;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;
import org.expressme.openid.*;

/** fixme: store nonce in database, prevent request-forgery, create HTTPSession on successfull login */

@Path("/sign-on")
public class SignonPlugin extends WebActivatorPlugin {

    private static Logger log = Logger.getLogger(SignonPlugin.class.getName());

    /** see also @de.deepamehta.plugins.accesscontrol.model.Credentials */
    private static final String ENCRYPTED_PASSWORD_PREFIX = "-SHA256-";

    private static final String USERNAME_TYPE_URI = "dm4.accesscontrol.username";
    private static final String USER_ACCOUNT_TYPE_URI = "dm4.accesscontrol.user_account";
    private static final String USER_PASSWORD_TYPE_URI = "dm4.accesscontrol.password";

    private static final String PERSON_TYPE_URI = "dm4.contacts.person";
    private static final String PERSON_NAME_TYPE_URI = "dm4.contacts.person_name";
    private static final String MAILBOX_TYPE_URI = "dm4.contacts.email_address";
    private static final String FIRSTNAME_TYPE_URI = "dm4.contacts.first_name";
    private static final String LASTNAME_TYPE_URI = "dm4.contacts.last_name";

    private static final String OPENID_CLAIMED_TYPE_URI = "org.deepamehta.openid.claimed_id";

    private static final String ATTR_MAC = "openid_mac";
    private static final String ATTR_ALIAS = "openid_alias";

    private static final long ONE_HOUR = 3600000;
    private static final long TWO_HOURS = 7200000;

    @Context
    private HttpServletRequest request;

    private OpenIdManager manager;

    private AccessControlService acService;

    public void init() {
        initTemplateEngine();
		//
        manager = new OpenIdManager();
        manager.setRealm("http://localhost:8080"); // change to your domain
        manager.setReturnTo("http://localhost:8080/sign-on/openid/response"); // change to your servlet url
    }

    @GET
    @Path("/openid/google")
    public String performGoogleAuthentication() {

        // imediatley checks/ requests https://www.google.com/accounts/o8/id to _receive_ an endpointURI
        // redirect to Google sign on page:
        Endpoint endpoint = manager.lookupEndpoint("Google");
        Association association = manager.lookupAssociation(endpoint);
        association.setMaxAge(TWO_HOURS); // after 2hrs a password prompt appears again
        //
        if (request.getSession(false) == null) {
            log.warning("There is no session which we could be using to transport our needs.. - CREATING one");
        }
        HttpSession session = request.getSession();
        // Equip session with a shared secret
        session.setAttribute(ATTR_MAC, association.getRawMacKey());
        session.setAttribute(ATTR_ALIAS, endpoint.getAlias());
        //
        String url = manager.getAuthenticationUrl(endpoint, association);
        URI location;
        try {
            location = new java.net.URI(url);
            throw new WebApplicationException(Response.seeOther(location).build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(SignonPlugin.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";

    }

    @GET
    @Path("/openid/yahoo")
    public String performYahooAuthentication() {

        // redirect to Google sign on page:
        Endpoint endpoint = manager.lookupEndpoint("Yahoo");
        Association association = manager.lookupAssociation(endpoint);
        association.setMaxAge(TWO_HOURS); // after 2hrs a password prompt appears again
        //
        if (request.getSession(false) == null) {
            log.warning("There is no session which we could be using to transport our needs.. - CREATING one");
        }
        HttpSession session = request.getSession();
        // Equip session with a shared secret
        session.setAttribute(ATTR_MAC, association.getRawMacKey());
        session.setAttribute(ATTR_ALIAS, endpoint.getAlias());
        //
        String url = manager.getAuthenticationUrl(endpoint, association);
        URI location;
        try {
            location = new java.net.URI(url);
            throw new WebApplicationException(Response.seeOther(location).build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(SignonPlugin.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";

    }

    @GET
    @Path("/openid/response")
    @Produces(MediaType.TEXT_HTML)
    public Viewable processOpenAuthenticationResponse(@QueryParam("openid.response_nonce") String nonce,
            @QueryParam("openid.op_endpoint") String endpoint, @QueryParam("openid.claimed_id") String openId,
            @HeaderParam("Cookie") ClientState clientState) {

        // 0.) Authenticate response
        Authentication authentication = authenticateIncomingRequest(request, openId);
        if (authentication == null) {
            throw new WebApplicationException(new Throwable("Authentication unsuccessfull."), Status.UNAUTHORIZED);
        }
        // 1.) parse request based on endpoint value set by AP
        String provider = "";
        if (endpoint.indexOf("google") != -1) {
            provider = "Google";
        } else if (endpoint.indexOf("yahoo") != -1) {
            provider = "Yahoo";
        }
        // 2.) check nonce (shall prevent "replay-attack")
        checkNonce(nonce);
        // 3.) try to relate response to an existing "user account"
        Topic userAccount = getUserAccountByOpenId(openId, provider);
        if (userAccount == null) {
            String email = authentication.getEmail();
            String new_username = email.substring(0, email.indexOf("@"));
            // fixme: permissions should not be set correctly cause of (yet) missing client-state (resp. session)
            Topic new_account = createUserAccountByOpenId(openId, new_username, email, authentication.getFirstname(),
                    authentication.getLastname(), clientState);
            viewData("title", "DeepaMehta Account Created");
            viewData("message", "On behalf of your successfull request DeepaMehta created a new user account.");
            viewData("username", new_account.getSimpleValue().toString());
            viewData("openid", openId);
        } else {
            log.info("Sign-on Module => User Account already known, logging in => " + userAccount.getSimpleValue());
            viewData("title", "Logged in via " + provider);
            viewData("message", "");
            createSession(userAccount.getSimpleValue().toString(), request);
            log.info("##### Logging in via OpenID-Request => SUCCESSFUL!" +
                "\n      ##### Could create a new session for " + userAccount.getSimpleValue().toString());
            try {
                URI location = new java.net.URI("http://localhost:8080/de.deepamehta.webclient");
                throw new WebApplicationException(Response.seeOther(location).build());
            } catch (URISyntaxException ex) {
                log.info("Redirecting failed cause of malformed URI"); // doing nothing..
            }
        }
        return getSignedOnView();

    }

    /** --- private helpers --- */

    private Authentication authenticateIncomingRequest(HttpServletRequest request, String openId) {
        // authenticate incoming request
        log.info("Open-ID Authentication for " + openId);
        byte[] mac_key = (byte[]) request.getSession().getAttribute(ATTR_MAC);
        String alias = (String) request.getSession().getAttribute(ATTR_ALIAS);
        Authentication authentication = manager.getAuthentication(request, mac_key, alias);
        if (authentication == null) {
            log.info("Request authentication failed with \"" + alias + "\" key:\""+mac_key+"\"");
            log.info("##### Logging in via OpenID-Request => FAILED!");
            return authentication;
        }
        return authentication;
    }

    private HttpSession createSession(String username, HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute("username", username);
        return session;
    }

    private void checkNonce(String nonce) {
        // check response_nonce to prevent replay-attack:
        // so we need to keep track of all nonces we handed out, no?
        if ( nonce == null || nonce.length() < 20 ) throw new OpenIdException("Verifying openid.response_nonce failed.");
        long nonceTime = getNonceTime(nonce);
        long diff = System.currentTimeMillis() - nonceTime;
        if ( diff < 0 ) diff = (-diff);
        if ( diff > ONE_HOUR ) throw new OpenIdException("Bad nonce time.");
        if ( isNonceExist(nonce) ) throw new OpenIdException("Verifiying openid.response_nonce failed.");
        storeNonce(nonce, nonceTime + TWO_HOURS);
    }

    private boolean isNonceExist(String nonce) {
        // TODO: check if nonce is exist in database:
        return false;
    }

    private void storeNonce(String nonce, long expires) {
        // TODO: store nonce in database:
    }

    private long getNonceTime(String nonce) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").parse(nonce.substring(0, 19) + "+0000").getTime();
        } catch(ParseException e) {
            throw new OpenIdException("Bad nonce time.");
        }
    }

    private RelatedTopic getUserAccountByOpenId(String openId, String provider) {
        Topic openIdTopic = null;
        if (provider.equals("Yahoo") && openId.indexOf("#") != -1) {
            // this seems to be the yahoo style of messing up my openId-url appending e.g. "#47478" or something
            openId = openId.substring(0, openId.indexOf("#"));
        }
        openIdTopic = dms.getTopic(OPENID_CLAIMED_TYPE_URI, new SimpleValue(openId), true);
        if (openIdTopic != null) {
            return openIdTopic.getRelatedTopic("dm4.core.composition", "dm4.core.child", "dm4.core.parent",
                "dm4.accesscontrol.user_account", true, false);
        } else {
            return null;
        }
    }

    private Topic createUserAccountByOpenId(String openId, String username, String email, String firstName,
            String lastName, ClientState clientState) {
        // DeepaMehtaTransaction tx = dms.begin
        if (!isUsernameAvailable(username)) throw new WebApplicationException(412);
        // fixme: user account needs to be able to edit himself
        CompositeValueModel userAccount = new CompositeValueModel()
                .put(USERNAME_TYPE_URI, username)
                .put(USER_PASSWORD_TYPE_URI, encryptPassword(""))
                .put(OPENID_CLAIMED_TYPE_URI, openId);
        // We are now skipping to relate any further personal information to a user account now (see also Migration1)
        /** CompositeValueModel personData =  new CompositeValueModel()
                .add(MAILBOX_TYPE_URI, new TopicModel(MAILBOX_TYPE_URI, new SimpleValue(email)));
        // fixme: using .put() results the folllowing RuntimeException (can not be true) is in this case a bad message:
        // "Invalid access to CompositeValueModel entry "dm4.contacts.email_address":
        // the caller assumes it to be multiple-value but it is single-value in" because it's actually multi-valued.
        CompositeValueModel nameData =  new CompositeValueModel()
                .put(FIRSTNAME_TYPE_URI, firstName)
                .put(LASTNAME_TYPE_URI, lastName);
        personData.put(PERSON_NAME_TYPE_URI, nameData);
        userAccount.put(PERSON_TYPE_URI, personData); **/
        // fixme: set user account to "Blocked" until verified
        // fixme: user has no password, normal login needs to be blocked!
        TopicModel userModel = new TopicModel(USER_ACCOUNT_TYPE_URI, userAccount);
        Topic user = dms.createTopic(userModel, clientState);
        return user;
    }

    private boolean isUsernameAvailable(String username) {
        // fixme: framework should also allow us to query case insensitve for a username
        Topic userName = dms.getTopic(USERNAME_TYPE_URI, new SimpleValue(username), true);
        return (userName == null) ? true : false;
    }

    private String encryptPassword(String password) {
        return ENCRYPTED_PASSWORD_PREFIX + JavaUtils.encodeSHA256(password);
    }

    /** --- routes --- */

    @GET
    @Path("/")
    @Produces("text/html")
    public Viewable getSignOnView() {
        // fixme: use acl service to check if a session already exists and if so, redirect to dm-webclient directly
        return view("index");
    }
    @GET
    @Path("/received")
    @Produces("text/html")
    public Viewable getSignedOnView() {
        return view("received");
    }

    /** --- Implementing PluginService Interfaces to consume AccessControlService --- */

    @Override
    @ConsumesService({
        "de.deepamehta.plugins.accesscontrol.service.AccessControlService"
    })
    public void serviceArrived(PluginService service) {
        if (service instanceof AccessControlService) {
            acService = (AccessControlService) service;
        }
    }

    @Override
    @ConsumesService({
        "de.deepamehta.plugins.accesscontrol.service.AccessControlService"
    })
    public void serviceGone(PluginService service) {
        if (service == acService) {
            acService = null;
        }
    }

}