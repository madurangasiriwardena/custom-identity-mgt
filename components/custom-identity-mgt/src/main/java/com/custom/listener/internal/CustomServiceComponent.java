package com.custom.listener.internal;

import com.custom.listener.listeners.ClaimRestrictingUserMgtEventListener;
import com.custom.listener.listeners.ExtendedUserMgtAuditLogger;
import com.custom.listener.listeners.UserExportListener;
import com.custom.listener.listeners.XACMLBasedUserOperationEventListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.entitlement.EntitlementService;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "custom.authz.xacml.component",
        immediate = true
)
public class CustomServiceComponent {

    private static final Log log = LogFactory.getLog(CustomServiceComponent.class);

    @SuppressWarnings("unchecked")
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            ctxt.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                    new XACMLBasedUserOperationEventListener(), null);

            ctxt.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                    new ExtendedUserMgtAuditLogger(), null);
            ctxt.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                    new UserExportListener(), null);
            ctxt.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                    new ClaimRestrictingUserMgtEventListener(), null);
            log.info("Custom identity management component activated successfully.");
        } catch (Throwable e) {
            log.error(e);
        }
    }

    @Reference(
            name = "custom.identity.entitlement.service",
            service = EntitlementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEntitlementService"
    )
    protected void setEntitlementService(EntitlementService entitlementService) {

        if (log.isDebugEnabled()) {
            log.debug("EntitlementService is set in the Application Authentication Framework bundle");
        }
        CustomDataholder.getInstance().setEntitlementService(entitlementService);
    }

    protected void unsetEntitlementService(EntitlementService entitlementService) {

        if (log.isDebugEnabled()) {
            log.debug("EntitlementService is unset in the Application Authentication Framework bundle");
        }
        CustomDataholder.getInstance().setEntitlementService(null);
    }

    @Reference(
            name = "custom.user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Application Authentication Framework bundle");
        }
        CustomDataholder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        CustomDataholder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "custom.registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is set in the Application Authentication Framework bundle");
        }
        CustomDataholder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        CustomDataholder.getInstance().setRegistryService(null);
    }

}
