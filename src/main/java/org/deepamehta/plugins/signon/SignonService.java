package org.deepamehta.plugins.signon;

import com.sun.jersey.api.view.Viewable;
import de.deepamehta.core.Topic;
import de.deepamehta.core.RelatedTopic;
import de.deepamehta.core.model.CompositeValueModel;
import de.deepamehta.core.model.SimpleValue;
import de.deepamehta.core.model.TopicModel;
import de.deepamehta.core.service.ClientState;
import de.deepamehta.core.util.JavaUtils;
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
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import org.expressme.openid.*;

/** fixme: store nonce in database, prevent request-forgery, create HTTPSession on successfull login */

@Path("/sign-on")
public class SignonService extends WebActivatorPlugin {

    private static Logger log = Logger.getLogger(SignonService.class.getName());

    /** see also @de.deepamehta.plugins.accesscontrol.model.Credentials */
    private static final String ENCRYPTED_PASSWORD_PREFIX = "-SHA256-";

    private static String USERNAME_TYPE_URI = "dm4.accesscontrol.username";
    private static String USER_ACCOUNT_TYPE_URI = "dm4.accesscontrol.user_account";
    private static String USER_PASSWORD_TYPE_URI = "dm4.accesscontrol.password";

    private static String PERSON_TYPE_URI = "dm4.contacts.person";
    private static String PERSON_NAME_TYPE_URI = "dm4.contacts.person_name";
    private static String MAILBOX_TYPE_URI = "dm4.contacts.email_address";
    private static String FIRSTNAME_TYPE_URI = "dm4.contacts.first_name";
    private static String LASTNAME_TYPE_URI = "dm4.contacts.last_name";

    private static String OPENID_CLAIMED_TYPE_URI = "org.deepamehta.openid.claimed_id";

    private static final long ONE_HOUR = 3600000;
    private static final long TWO_HOURS = 7200000;

    private OpenIdManager manager;

    public void init() {
        setupRenderContext();
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
        // fixme: set requested attributes more nicely:
        // * (needed) E-Mail-Adresse
        // * (to be removed) General User Account Information
        Association association = manager.lookupAssociation(endpoint);
        association.setMaxAge(TWO_HOURS); // after 2hrs a password prompt appears again
        String url = manager.getAuthenticationUrl(endpoint, association);
        URI location;
        try {
            location = new java.net.URI(url);
            throw new WebApplicationException(Response.seeOther(location).build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(SignonService.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";

    }

    @GET
    @Path("/openid/yahoo")
    public String performYahooAuthentication() {

        // imediatley checks/ requests https://www.google.com/accounts/o8/id to _receive_ an endpointURI
        // redirect to Google sign on page:
        Endpoint endpoint = manager.lookupEndpoint("Yahoo");
        // fixme: set requested attributes more nicely:
        // * (needed) E-Mail-Adresse
        // * (to be removed) General User Account Information
        Association association = manager.lookupAssociation(endpoint);
        association.setMaxAge(TWO_HOURS); // after 2hrs a password prompt appears again
        String url = manager.getAuthenticationUrl(endpoint, association);
        URI location;
        try {
            location = new java.net.URI(url);
            throw new WebApplicationException(Response.seeOther(location).build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(SignonService.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";

    }

    @GET
    @Path("/openid/response")
    @Produces(MediaType.TEXT_HTML)
    public Viewable processOpenAuthenticationResponse(@QueryParam("openid.response_nonce") String nonce,
            @QueryParam("openid.op_endpoint") String endpoint,
            @QueryParam("openid.ext1.value.firstname") String firstNameGoogle,
            @QueryParam("openid.ext1.value.lastname") String lastNameGoogle,
            @QueryParam("openid.ext1.value.email") String emailGoogle,
            @QueryParam("openid.ax.value.fullname") String fullNameYahoo,
            @QueryParam("openid.ax.value.email") String emailYahoo,
            @QueryParam("openid.claimed_id") String openId,
            @HeaderParam("Cookie") ClientState clientState,
            @Context HttpHeaders headers) {

        // fixme: what exactly happens if authentication fails? it just never reaches us, i guess.
        // fixme: find out how we can check if the request has the right origin?
        //		  or in other words: how can we prevent people just constructing a valid request? it might be possible.
        /** MultivaluedMap<String, String> responseHeaders = headers.getRequestHeaders();
        Set<String> keys = responseHeaders.keySet();
        for (String key : keys) {
            log.info("HTTP Header : " + key + "; " + headers.getRequestHeader(key).get(0).toString());
        } **/
        // parse request based on endpoint value set by AP
        String provider = "";
        String firstName = "", lastName = "", eMail = "", username = "";
        if (endpoint.indexOf("google") != -1) {
            provider = "Google";
            firstName = firstNameGoogle;
            lastName = lastNameGoogle;
            eMail = emailGoogle;
            username = emailGoogle.substring(0, emailGoogle.indexOf("@"));
        } else if (endpoint.indexOf("yahoo") != -1) {
            provider = "Yahoo";
            String[] name = fullNameYahoo.split(" "); // split fullname by whitespace
            firstName = name[0];
            lastName = name[1];
            eMail = emailYahoo;
            username = emailYahoo.substring(0, emailYahoo.indexOf("@"));
        }
        // process received values from AP
        try {
            log.info("---- ");
            log.info("GOT OpenId Response.. from Google with nonce: " + nonce);
            log.info("User ID: " + openId);
            log.info("E-Mail: " + eMail);
            log.info("--- ");
            // 1.) check nonce (shall prevent "replay-attack")
            checkNonce(nonce);
            // 2.) fixme: create "Session" (needs extended dm-framework or a HttpServletRequest to be injected)
            //	   @see AccessControlPlugin
            // 3.) create new "user account", if none with that id exist in database:
            Topic userAccount = getUserAccountByOpenId(openId);
            if (userAccount == null) {
                createUserAccountByOpenId(openId, username, eMail, firstName, lastName, clientState);
                context.setVariable("title", "DeepaMehta Account Created");
                context.setVariable("message", "Your account request was successfull, "
                        + "we created a new user account for you.");
            } else {
                log.info("Sign-on Module => User Account already known, logging in => " + userAccount.getSimpleValue());
                context.setVariable("title", "Logged in via " + provider);
                context.setVariable("message", "");
                // fixme: redirection, at best, with a working user session
                // fixme: to create a usersession with the help of the ACL-Modules
                //        createHttpSession(HttpServletRequest),  we would need access to the HttpServletRequest-Object
                /** try {
                    URI location = new java.net.URI("http://localhost:8080/de.deepamehta.webclient");
                    throw new WebApplicationException(Response.seeOther(location).build());
                } catch (URISyntaxException ex) {
                    log.info("Redirecting failed cause of malformed URI");
                } */
            }
            return getSignedOnView(clientState);
        } catch (Exception e) {
            log.warning(e.getMessage());
            throw new WebApplicationException(e);
        }
    }

    /** --- private helpers --- */

    private void checkNonce(String nonce) {
        // check response_nonce to prevent replay-attack:
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

    private RelatedTopic getUserAccountByOpenId(String openId) {
        Topic openIdTopic = dms.getTopic(OPENID_CLAIMED_TYPE_URI, new SimpleValue(openId), true, null);
        if (openIdTopic != null) {
            return openIdTopic.getRelatedTopic("dm4.core.composition", "dm4.core.child", "dm4.core.parent",
                "dm4.accesscontrol.user_account", true, false, null);
        } else {
            return null;
        }
    }

    private Topic createUserAccountByOpenId(String openId, String username, String email, String firstName,
            String lastName, ClientState clientState) {
        if (!isUsernameAvailable(username, clientState)) throw new WebApplicationException(412);
        // fixme: user account needs to be able to edit himself
        CompositeValueModel userAccount = new CompositeValueModel()
                .put(USERNAME_TYPE_URI, username)
                .put(USER_PASSWORD_TYPE_URI, encryptPassword(""))
                .put(OPENID_CLAIMED_TYPE_URI, openId);
        CompositeValueModel personData =  new CompositeValueModel()
                .add(MAILBOX_TYPE_URI, new TopicModel(MAILBOX_TYPE_URI, new SimpleValue(email)));
        // fixme: using .put() results the folllowing RuntimeException (can not be true) is in this case a bad message:
        // "Invalid access to CompositeValueModel entry "dm4.contacts.email_address":
        // the caller assumes it to be multiple-value but it is single-value in" because it's actually multi-valued.
        CompositeValueModel nameData =  new CompositeValueModel()
                .put(FIRSTNAME_TYPE_URI, firstName)
                .put(LASTNAME_TYPE_URI, lastName);
        personData.put(PERSON_NAME_TYPE_URI, nameData);
        userAccount.put(PERSON_TYPE_URI, personData);
        // fixme: set user account to "Blocked" until verified
        // fixme: user has no password, normal login needs to be blocked!
        TopicModel userModel = new TopicModel(USER_ACCOUNT_TYPE_URI, userAccount);
        Topic user = dms.createTopic(userModel, clientState);
        return user;
    }

    private boolean isUsernameAvailable(String username, ClientState clientState) {
        // fixme: framework should also allow us to query case insensitve for a username
        Topic userName = dms.getTopic(USERNAME_TYPE_URI, new SimpleValue(username), true, clientState);
        return (userName == null) ? true : false;
    }

    private String encryptPassword(String password) {
        return ENCRYPTED_PASSWORD_PREFIX + JavaUtils.encodeSHA256(password);
    }

    /** --- routes --- */

    @GET
    @Path("/")
    @Produces("text/html")
    public Viewable getSignOnView(@HeaderParam("Cookie") ClientState clientState) {
        // fixme: use acl service to check if a session already exists and if so, redirect to dm-webclient directly
        return view("index");
    }
    @GET
    @Path("/received")
    @Produces("text/html")
    public Viewable getSignedOnView(@HeaderParam("Cookie") ClientState clientState) {
        return view("received");
    }

}
