package com.custom.listener.internal;

import org.wso2.carbon.identity.entitlement.EntitlementService;
import org.wso2.carbon.identity.user.account.association.UserAccountConnector;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class CustomDataholder {

    private static CustomDataholder instance = new CustomDataholder();
    private EntitlementService entitlementService = null;
    private UserAccountConnector userAccountConnector = null;
    private RealmService realmService = null;
    private RegistryService registryService = null;

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }

    public static CustomDataholder getInstance() {

        return instance;
    }

    public EntitlementService getEntitlementService() {

        return entitlementService;
    }

    public void setEntitlementService(EntitlementService entitlementService) {

        this.entitlementService = entitlementService;
    }

}
