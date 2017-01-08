package com.custom.listener.handler.provisioning;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl
        .DefaultStepBasedSequenceHandler;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.AssociatedAccountDTO;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ExtendedStepBasedSequenceHandler extends DefaultStepBasedSequenceHandler {

    private static final Log log = LogFactory.getLog(ExtendedStepBasedSequenceHandler.class);

    protected void handleJitProvisioning(String subjectIdentifier, AuthenticationContext context,
                                         List<String> mappedRoles, Map<String, String> extAttributesValueMap)
            throws FrameworkException {

        if (mappedRoles == null) {
            mappedRoles = new ArrayList<>();
        }
        String userStoreDomain = null;
        String provisioningClaimUri = context.getExternalIdP()
                .getProvisioningUserStoreClaimURI();
        String provisioningUserStoreId = context.getExternalIdP().getProvisioningUserStoreId();

        if (provisioningUserStoreId != null) {
            userStoreDomain = provisioningUserStoreId;
        } else if (provisioningClaimUri != null) {
            userStoreDomain = extAttributesValueMap.get(provisioningClaimUri);
        }
        mappedRoles.add(userStoreDomain + "/" + context.getSequenceConfig().getApplicationConfig().getApplicationName
                ());

        super.handleJitProvisioning(subjectIdentifier, context, mappedRoles, extAttributesValueMap);


        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantId(IdentityTenantUtil.getTenantId(context.getTenantDomain()));
            carbonContext.setTenantDomain(context.getTenantDomain());
            carbonContext.setUsername(userStoreDomain + "/" + subjectIdentifier);

            boolean associated = false;
            AssociatedAccountDTO[] associatedIDs = UserProfileAdmin.getInstance().getAssociatedIDs();
            for (AssociatedAccountDTO associatedAccountDTO : associatedIDs) {
                if (subjectIdentifier.equals(associatedAccountDTO.getUsername()) && context.getExternalIdP()
                        .getIdPName().equals(associatedAccountDTO.getIdentityProviderName())) {
                    associated = true;
                    break;
                }
            }

            if (!associated) {
                UserProfileAdmin.getInstance().associateID(context.getExternalIdP().getIdPName(), subjectIdentifier);
            }

        } catch (UserProfileException e) {
            log.error("Error while associating federated user account.", e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
