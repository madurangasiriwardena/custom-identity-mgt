package com.custom.listener.listeners;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Iterator;
import java.util.Map;

public class ClaimRestrictingUserMgtEventListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(ClaimRestrictingUserMgtEventListener.class);

    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 2;
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims,
                                           String profileName, UserStoreManager userStoreManager) throws
            UserStoreException {

        if (!isEnable()) {
            return true;
        }
        String domainName = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());

        for (Iterator<Map.Entry<String, String>> it = claims.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, String> entry = it.next();
            try {
                ClaimMapping claimMapping = userStoreManager.getClaimManager().getClaimMapping(entry.getKey());
                if (claimMapping != null) {
                    String mappedAttribute = claimMapping.getMappedAttribute(domainName);
                    if ("NA".equalsIgnoreCase(mappedAttribute)) {
                        it.remove();
                    }
                }
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                log.error("Error while removing restricted claims", e);
            }
        }
        return true;
    }
}
