package org.deepamehta.plugins.signon.migrations;

import de.deepamehta.core.AssociationDefinition;
import java.util.logging.Logger;
import de.deepamehta.core.service.Migration;
import de.deepamehta.core.TopicType;
import de.deepamehta.core.model.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class Migration1 extends Migration {

    private Logger logger = Logger.getLogger(getClass().getName());

    private String PERSON_TYPE_URI = "dm4.contacts.person";
    private String USER_ACCOUNT_TYPE_URI = "dm4.accesscontrol.user_account";
	private String OPENID_CLAIMED_TYPE_URI = "org.deepamehta.openid.claimed_id";

    @Override
    public void run() {

        TopicType account = dms.getTopicType(USER_ACCOUNT_TYPE_URI);

		// 1) Create "OpenId"-Type
		TopicTypeModel openIdModel = new TopicTypeModel(OPENID_CLAIMED_TYPE_URI ,"OpenID", "dm4.core.text");
		TopicType openId = dms.createTopicType(openIdModel, null);
		Set<IndexMode> indexModes = new HashSet<IndexMode>();
		indexModes.add(IndexMode.KEY);
		openId.setIndexModes(indexModes);

		// 2) Marry "OpenId"-Type with DeepaMehta's "User Account"-Type
		account.addAssocDef(new AssociationDefinitionModel("dm4.core.composition_def", USER_ACCOUNT_TYPE_URI,
                OPENID_CLAIMED_TYPE_URI, "dm4.core.one", "dm4.core.one"));

		// 3) If not already done, enrich the "User Account"-Type about a "Person"-Type
        /** Collection<AssociationDefinition> childTypes = account.getAssocDefs();
        boolean hasPersonAsChild = false;
        for (AssociationDefinition child : childTypes) {
            if (child.getChildTypeUri().equals(PERSON_TYPE_URI)) hasPersonAsChild = true;
        }
        if (!hasPersonAsChild) {
            logger.info("Sign-on Migration1 => Enriching \"User Account\"-Type about \"Person\"-Type");
            account.addAssocDef(new AssociationDefinitionModel("dm4.core.aggregation_def", USER_ACCOUNT_TYPE_URI,
                PERSON_TYPE_URI, "dm4.core.one", "dm4.core.one"));
        } else {
            logger.info("Sign-on Migration1 => NOT Enriching \"User Account\"-Type about \"Person\"-Type - Already done!");
        } **/

    }

}