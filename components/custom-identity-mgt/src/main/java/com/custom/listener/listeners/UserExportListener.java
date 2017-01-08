package com.custom.listener.listeners;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class UserExportListener extends AbstractIdentityUserOperationEventListener {


    private static final Log audit = CarbonConstants.AUDIT_LOG;
    private static final Log log = LogFactory.getLog(UserExportListener.class);

    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 10000;
    }

    @Override
    public boolean doPreDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }

        String logPath = CarbonUtils.getCarbonLogsPath() + "/delete.txt";

        Claim[] userClaimValues = userStoreManager.getUserClaimValues(userName, "default");

        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(logPath, true)))) {

            StringBuffer logString = new StringBuffer();
            logString.append("Deleting user : ")
                    .append(userName)
                    .append("\nTime :")
                    .append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()))
                    .append("\nUser store domain : ")
                    .append(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()))
                    .append("\nTenant domain : ")
                    .append(IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()))
                    .append("\nUser attributes : ");
            if (userClaimValues != null) {
                for (Claim claim : userClaimValues) {
                    logString.append("\n\t").append(claim.getClaimUri()).append(" : ").append(claim.getValue());
                }
            }
            logString.append("\nDeleted by : ")
                    .append(getUser())
                    .append("\n=====================================================================================");
            writer.println(logString);
        } catch (IOException e) {
            log.error("Error while exporting the user details.", e);
        }

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

    @Override
    public boolean doPostDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {
        if (!isEnable()) {
            return true;
        }
        removeAssociateID(userName, UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()));
        return true;
    }


    private void removeAssociateID(String username, String userStoreDomain) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sql;
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            sql = "DELETE FROM IDN_ASSOCIATED_ID WHERE TENANT_ID = ? AND USER_NAME = ? AND DOMAIN_NAME = ?";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, username);
            prepStmt.setString(3, userStoreDomain);

            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            log.error("Error occurred while removing associated ID", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

    }

}
