package com.custom.listener.listeners;

import com.custom.listener.constants.CustomConstants;
import com.custom.listener.exception.CustomException;
import com.custom.listener.internal.CustomDataholder;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaxen.JaxenException;
import org.wso2.balana.utils.Constants.PolicyConstants;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.common.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.stream.XMLStreamException;

public class XACMLBasedUserOperationEventListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(XACMLBasedUserOperationEventListener.class);
    private static final String DECISION_XPATH = "//ns:Result/ns:Decision/text()";
    private static final String XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
    private static final String XACML_NS_PREFIX = "ns";
    private static final String RULE_EFFECT_PERMIT = "Permit";
    private static final String RULE_EFFECT_NOT_APPLICABLE = "NotApplicable";
    public static final String ACTION_UPDATE_CLAIMS = "update-claims";

    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 5;
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {
        if (!isEnable()) {
            return true;
        }
        String invokerUsername = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        if (invokerUsername != null && !invokerUsername.equals(userName)) {
            return isAuthorized(invokerUsername, userName, userStoreDomain, tenantDomain);
        } else {
            return true;
        }
    }

    private boolean isAuthorized(String invokerUsername, String username, String userStoreDomain, String tenantDomain)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("In policy authorization flow...");
        }
        log.info("In policy authorization flow...");

        try {

            RequestDTO requestDTO = createRequestDTO(invokerUsername, username, userStoreDomain, tenantDomain);
            RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);

            String requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);
            if (log.isDebugEnabled()) {
                log.debug("XACML Authorization request :\n" + requestString);
            }
            String responseString =
                    CustomDataholder.getInstance().getEntitlementService().getDecision(requestString);
            if (log.isDebugEnabled()) {
                log.debug("XACML Authorization response :\n" + responseString);
            }
            String authzResponse = evaluateXACMLResponse(responseString);
            boolean isAuthorized = false;
            if (RULE_EFFECT_NOT_APPLICABLE.equalsIgnoreCase(authzResponse)) {
                log.warn(String.format(
                        "No applicable rule for service provider , Hence authorizing the user by default. " +
                                "Add an authorization policy (or unset authorization) to fix this warning."));
                isAuthorized = true;
            } else if (RULE_EFFECT_PERMIT.equalsIgnoreCase(authzResponse)) {
                isAuthorized = true;
            }
            if (!isAuthorized) {
                throw new UserStoreException("User is not authorized to update the profile");
            } else {
                return true;
            }
        } catch (PolicyBuilderException e) {
            log.error("Policy Builder Exception occurred", e);
        } catch (EntitlementException e) {
            log.error("Entitlement Exception occurred", e);
        } catch (CustomException e) {
            log.error("Error when evaluating the XACML response", e);
        }

        return false;
    }

    private RequestDTO createRequestDTO(String invokerUsername, String username, String userStoreDomain, String
            tenantDomain) {

        List<RowDTO> rowDTOs = new ArrayList<>();
        RowDTO actionDTO =
                createRowDTO(ACTION_UPDATE_CLAIMS,
                        CustomConstants.AUTH_ACTION_ID, CustomConstants.ACTION_CATEGORY);

        RowDTO usernameDTO =
                createRowDTO(username,
                        CustomConstants.USERNAME_ID, CustomConstants.USER_CATEGORY);
        RowDTO userStoreDomainDTO =
                createRowDTO(userStoreDomain,
                        CustomConstants.USER_STORE_ID, CustomConstants.USER_CATEGORY);
        RowDTO userTenantDomainDTO =
                createRowDTO(tenantDomain,
                        CustomConstants.USER_TENANT_DOMAIN_ID, CustomConstants.USER_CATEGORY);
        RowDTO subjectDTO =
                createRowDTO(invokerUsername, PolicyConstants.SUBJECT_ID_DEFAULT, PolicyConstants.SUBJECT_CATEGORY_URI);
        rowDTOs.add(subjectDTO);

        rowDTOs.add(actionDTO);
        rowDTOs.add(usernameDTO);
        rowDTOs.add(userStoreDomainDTO);
        rowDTOs.add(userTenantDomainDTO);
        RequestDTO requestDTO = new RequestDTO();
        requestDTO.setRowDTOs(rowDTOs);
        return requestDTO;
    }

    private RowDTO createRowDTO(String resourceName, String attributeId, String categoryValue) {

        RowDTO rowDTOTenant = new RowDTO();
        rowDTOTenant.setAttributeValue(resourceName);
        rowDTOTenant.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
        rowDTOTenant.setAttributeId(attributeId);
        rowDTOTenant.setCategory(categoryValue);
        return rowDTOTenant;

    }

    private String evaluateXACMLResponse(String xacmlResponse) throws CustomException {

        try {
            AXIOMXPath axiomxPath = new AXIOMXPath(DECISION_XPATH);
            axiomxPath.addNamespace(XACML_NS_PREFIX, XACML_NS);
            OMElement rootElement =
                    new StAXOMBuilder(new ByteArrayInputStream(xacmlResponse.getBytes(StandardCharsets.UTF_8)))
                            .getDocumentElement();
            return axiomxPath.stringValueOf(rootElement);
        } catch (JaxenException | XMLStreamException e) {
            throw new CustomException("Exception occurred when getting decision from xacml response.", e);
        }
    }
}
