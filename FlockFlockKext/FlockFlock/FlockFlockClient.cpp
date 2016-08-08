//
//  FlockFlockClient.cpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include "FlockFlockClient.hpp"

#define super IOUserClient
OSDefineMetaClassAndStructors(com_zdziarski_driver_FlockFlockClient, IOUserClient)

const IOExternalMethodDispatch
com_zdziarski_driver_FlockFlockClient::sMethods[kFlockFlockRequestMethodCount] =
{
    { &com_zdziarski_driver_FlockFlockClient::sClearConfiguration, 0, SKEY_LEN, 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sAddClientPolicy, 0, sizeof(struct _FlockFlockClientPolicy), 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sStartFilter, 0, 0, 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sStopFilter, 0, SKEY_LEN, 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sRespond, 0, sizeof(struct policy_response), 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sSetAgentPID, 1, SKEY_LEN, 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sSetDaemonPID, 1, SKEY_LEN, 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sGenTicket, 0, 0, 0, 0 },
    { &com_zdziarski_driver_FlockFlockClient::sFilterStatus, 0, 0, 0, 0 }
};

IOReturn com_zdziarski_driver_FlockFlockClient::sRespond(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sRespond\n");
    struct policy_response *response = (struct policy_response *)args->structureInput;
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;

    switch(response->response_type) {
        case(FFQ_ACCESS):
            bcopy(args->structureInput, &me->m_driver->policyContext.response, sizeof(struct policy_response));
            IOLockUnlock(me->m_driver->policyContext.reply_lock);
            break;
    }
    return KERN_SUCCESS;
}

IOReturn com_zdziarski_driver_FlockFlockClient::sFilterStatus(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sFilterStatus\n");
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    if (me->m_driver->isFilterActive() == true) {
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}

IOReturn com_zdziarski_driver_FlockFlockClient::sSetAgentPID(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sSetPID\n");
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    me->m_driver->setAgentPID(args->scalarInput[0], (unsigned char *)args->structureInput);
    return KERN_SUCCESS;
}

IOReturn com_zdziarski_driver_FlockFlockClient::sSetDaemonPID(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sSetDaemonPID\n");
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    me->m_driver->setDaemonPID(args->scalarInput[0], (unsigned char *)args->structureInput);
    return KERN_SUCCESS;
}

IOReturn com_zdziarski_driver_FlockFlockClient::sClearConfiguration(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sClearConfiguration\n");
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    me->m_driver->clearAllRules((unsigned char *)args->structureInput);
    return KERN_SUCCESS;
}

IOReturn com_zdziarski_driver_FlockFlockClient::sAddClientPolicy(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sAddClientPolicy\n");

    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    FlockFlockClientPolicy clientPolicy = (FlockFlockClientPolicy) args->structureInput;
  
    /* sanitize input */

    if (clientPolicy->ruleClass > kFlockFlockPolicyClassCount)
        return KERN_INVALID_VALUE;
    if (clientPolicy->ruleType > kFlockFlockPolicyTypeCount)
        return KERN_INVALID_VALUE;
    
    clientPolicy->processName[PATH_MAX-1] = 0;
    clientPolicy->rulePath[PATH_MAX-1] = 0;
    
    return me->m_driver->addClientPolicy(clientPolicy);
}

IOReturn com_zdziarski_driver_FlockFlockClient::sGenTicket(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sGenTicket");
    
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    bool success = me->m_driver->genTicket(me->m_taskIsAdmin);
    if (success == true)
        return KERN_SUCCESS;
    return KERN_FAILURE;
}


IOReturn com_zdziarski_driver_FlockFlockClient::sStartFilter(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    bool success = me->m_driver->startFilter();
    if (success == true)
        return KERN_SUCCESS;
    return KERN_FAILURE;
}

IOReturn com_zdziarski_driver_FlockFlockClient::sStopFilter(OSObject *target, void *reference, IOExternalMethodArguments *args)
{
    IOLog("FlockFlockClient::sStopFilter\n");
    com_zdziarski_driver_FlockFlockClient *me = (com_zdziarski_driver_FlockFlockClient *)target;
    bool success = me->m_driver->stopFilter((unsigned char *)args->structureInput);
    IOLog("FlockFlockClient::sStopFilter: success = %d\n", success);
    if (success == true)
        return KERN_SUCCESS;
    return KERN_FAILURE;
}

IOReturn com_zdziarski_driver_FlockFlockClient::externalMethod(uint32_t selector, IOExternalMethodArguments *args, IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)
{
    if (selector >= kFlockFlockRequestMethodCount)
        return kIOReturnUnsupported;
    
    dispatch = (IOExternalMethodDispatch *)&sMethods[selector];
    target = this;
    reference = NULL;
    return super::externalMethod(selector, args, dispatch, target, reference);
}

bool com_zdziarski_driver_FlockFlockClient::initWithTask(task_t owningTask, void *securityToken, UInt32 type, OSDictionary *properties)
{    
    IOLog("FlockFlockClient::initWithTask client init\n");
    
    if (!owningTask)
        return false;
    
    if (! super::initWithTask(owningTask, securityToken, type, properties))
        return false;
    
    m_task = owningTask;
    m_taskIsAdmin = false;
    
    IOReturn ret = clientHasPrivilege(securityToken, kIOClientPrivilegeAdministrator);
    if (ret == kIOReturnSuccess)
    {
        m_taskIsAdmin = true;
    }
    
    return true;
}

bool com_zdziarski_driver_FlockFlockClient::start(IOService *provider)
{
    IOLog("FlockFlockClient::start client start\n");
    if (! super::start(provider))
        return false;
    
    m_driver = OSDynamicCast(com_zdziarski_driver_FlockFlock, provider);
    if (!m_driver)
        return false;
    return true;
}

IOReturn com_zdziarski_driver_FlockFlockClient::clientClose(void)
{
    IOLog("FlockFlockClient::clientClose client close\n");
    m_driver->clearMachPort();
    terminate();
    return kIOReturnSuccess;
}

IOReturn com_zdziarski_driver_FlockFlockClient::registerNotificationPort(mach_port_t port, UInt32 type, io_user_reference_t refCon)
{
    IOLog("FlockFlockClient::registerNotificationPort reference: %d\n", (int)refCon);
    bool ret = m_driver->setMachPort(port, m_taskIsAdmin);
    if (ret == true) {
        IOLog("FlockFlockClient::registerNotificationPort successful\n");
        return kIOReturnSuccess;
    }
    IOLog("FlockFlockClient::registerNotificationPort failed\n");
    return kIOReturnInvalid;
}

void com_zdziarski_driver_FlockFlockClient::stop(IOService *provider)
{
    super::stop(provider);
}

void com_zdziarski_driver_FlockFlockClient::free(void)
{
    super::free();
}

