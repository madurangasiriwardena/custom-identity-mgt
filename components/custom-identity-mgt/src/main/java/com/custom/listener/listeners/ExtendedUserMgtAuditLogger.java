package com.custom.listener.listeners;

import org.apache.commons.logging.Log;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.user.mgt.listeners.UserMgtAuditLogger;

import java.util.Arrays;
import java.util.Map;

public class ExtendedUserMgtAuditLogger extends UserMgtAuditLogger {


    private static final Log audit = CarbonConstants.AUDIT_LOG;

    //    private static final Log delete = LogFactory.getLog("DELETE_LOG");;
    private static final String SUCCESS = "Success";

    private static String AUDIT_MESSAGE = "Initiator : %s | Action : %s | Target : %s | Data : { %s } | Result : %s ";

    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 7;
    }

    public boolean doPostAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                 String profile, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        StringBuilder builder = new StringBuilder();
        if (roleList != null) {
            for (int i = 0; i < roleList.length; i++) {
                builder.append(roleList[i] + ",");
            }
        }
        audit.info(String.format(AUDIT_MESSAGE, getUser(), "Add User", UserCoreUtil.addDomainToName(userName,
                UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())), "Roles :" + builder.toString()
                , SUCCESS));
        return true;
    }

    public boolean doPostDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        audit.info(String.format(AUDIT_MESSAGE, getUser(), "Delete User",
                UserCoreUtil.addDomainToName(userName, UserCoreUtil.getDomainName(userStoreManager
                        .getRealmConfiguration())), "", SUCCESS));

//        delete.info(String.format(AUDIT_MESSAGE, getUser(), "Delete User",
//                UserCoreUtil.addDomainToName(userName,UserCoreUtil.getDomainName(userStoreManager
// .getRealmConfiguration())), "", SUCCESS));

        return true;
    }

    public boolean doPostUpdateCredential(String userName, Object credential, UserStoreManager userStoreManager) throws
            UserStoreException {

        if (!isEnable()) {
            return true;
        }

        audit.info(String.format(AUDIT_MESSAGE, getUser(), "Change Password by User",
                UserCoreUtil.addDomainToName(userName,
                        UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())), "", SUCCESS));
        return true;
    }

    public boolean doPreUpdateCredentialByAdmin(String userName, Object newCredential, UserStoreManager
            userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        audit.info(String.format(AUDIT_MESSAGE, getUser(), "Change Password by Administrator",
                UserCoreUtil.addDomainToName(userName,
                        UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())), "", SUCCESS));
        return true;
    }

    public boolean doPostUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles,
                                              UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        audit.info(String.format(AUDIT_MESSAGE, getUser(), "Update Roles of User",
                UserCoreUtil.addDomainToName(userName, UserCoreUtil.getDomainName(userStoreManager
                        .getRealmConfiguration())),
                "Roles : " + Arrays.toString(newRoles), SUCCESS));
        return true;
    }

    private String getUser() {
        String user = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (user != null) {
            user = user + "@" + CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        } else {
            user = CarbonConstants.REGISTRY_SYSTEM_USERNAME;
        }
        return user;
    }

}
