//
//  FlockFlockClientShared.h
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#ifndef FlockFlockClientShared_h
#define FlockFlockClientShared_h

#define PERSISTENCE
#define IOLog(...)
#define FLOCKFLOCK_VERSION  "alpha_0.0.25_persistence_unloadable"

#define DRIVER "com_zdziarski_driver_FlockFlock"
#define SKEY_LEN 32

#define FF_FILEOP_READ      0x01
#define FF_FILEOP_WRITE     0x02
#define FF_FILEOP_CREATE    0x04

enum FlockFlockRequestCode {
    kFlockFlockRequestClearConfiguration,
    kFlockFlockRequestAddClientRule,
    kFlockFlockRequestStartFilter,
    kFlockFlockRequestStopFilter,
    kFlockFlockRequestPolicyResponse,
    kFlockFlockAssignAgentPID,
    kFlockFlockAssignDaemonPID,
    kFlockFlockGenTicket,
    kFlockFlockFilterStatus,
    kFlockFlockRequestMethodCount
};

enum FlockFlockPolicyType {
    kFlockFlockPolicyTypePathPrefix,
    kFlockFlockPolicyTypeFilePath,
    kFlockFlockPolicyTypePathSuffix,
    
    kFlockFlockPolicyTypeCount
};

enum FlockFlockPolicyClass {
    kFlockFlockPolicyClassWhitelistAllMatching,
    kFlockFlockPolicyClassBlacklistAllMatching,
    kFlockFlockPolicyClassWatch,
    
    kFlockFlockPolicyClassCount
};

typedef struct _FlockFlockClientPolicy {
    enum FlockFlockPolicyClass ruleClass;
    enum FlockFlockPolicyType ruleType;
    char processName[PATH_MAX];
    char rulePath[PATH_MAX];
    int32_t temporaryRule;
    int32_t temporaryPid;
    int32_t operations;
    char skey[SKEY_LEN];
} *FlockFlockClientPolicy;

typedef struct _FlockFlockPolicy {
    struct _FlockFlockClientPolicy data;
    struct _FlockFlockPolicy *next;
} *FlockFlockPolicy;

typedef FlockFlockPolicy FlockFlockPolicyHierarchy;

#define FFQ_ACCESS  0x0100
#define FFQ_SECKEY  0x0101
#define FFQ_STOPPED 0x0102

struct policy_query {
    pid_t pid;
    char path[PATH_MAX];
    char process_name[PATH_MAX];
    uint32_t security_token;
    int32_t operation;
};

struct policy_response {
    pid_t pid;
    char path[PATH_MAX];
    uint32_t security_token;
    uint32_t response;
    uint32_t response_type;
    char skey[SKEY_LEN];
};

struct ff_basic_msg /* generic mach message */
{
    mach_msg_header_t header;
    uint32_t query_type;
};

struct policy_query_msg
{
    mach_msg_header_t header;
    uint32_t query_type;
    struct policy_query query;
};

struct skey_msg
{
    mach_msg_header_t header;
    uint32_t query_type;
    char skey[SKEY_LEN];
};

#endif /* FlockFlockClientShared_h */
