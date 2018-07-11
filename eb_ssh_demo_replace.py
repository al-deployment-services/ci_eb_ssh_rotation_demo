from lib import al_ci_client
import boto3
from botocore.exceptions import ClientError
import json
from Crypto.PublicKey import RSA
import logging
import requests
import time, datetime
import threading, sys
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

##############################
# Parameters for secret manager
secret_name = "vpc-d58792ac"
endpoint_url = "https://secretsmanager.us-west-2.amazonaws.com"
region_name = "us-west-2"
kms_arn = "arn:aws:kms:us-west-2:989608343549:key/ccc52fc7-740e-455e-a644-ed9b9ebdb061"
vpc_id = "vpc-d58792ac"
user_name = "alertlogic"

# Parameters for Elastic Beanstalk
# Demo EB taken from : https://github.com/coaic/eb-deployment-boto-scripts/blob/master/create_beanstalk_with_eb_api.py
region = "us-west-2"
vpc_id = "vpc-d58792ac"
instance_security_group = "sg-0cac737c"
webserver_subnets = "subnet-6667ef2d,subnet-3b541061,subnet-3b187642"
instance_type = 't2.micro'
healthcheck_url ='/'
wait_for_green = 5
cool_down = str(60 * 6)
autoscale_max_instance = '4'
autoscale_min_instance = '1'
rolling_update_batch_percent = '30'
update_level = 'patch'
managed_actions_enabled ='true'
preferred_starttime = "Sun:10:00"
ssh_key_name = 'welly_pst_lab'
ssh_restrictions = 'tcp,22,22,73.32.16.208/32'
instance_profile = 'aws-elasticbeanstalk-ec2-role'
service_role = 'aws-elasticbeanstalk-service-role'
application_name = 'test-scan-1'
application_description = 'Test application for demo'
environment_name = "%s-blue" % (application_name)
notification_email = 'welly.siauw@alertlogic.com'
environment_description = 'blue environment'
template_name = 'blue_v1'
solution_stack = '64bit Amazon Linux 2018.03 v3.0.1 running Tomcat 8.5 Java 8'
template_description = 'blue environment'
application_file = "java-tomcat-v2-syslog.zip"
application_version = "1"
target_s3_bucket = "wellysiauw-eb-scan-test-app"
option_settings = [
    {
        "OptionName": "IamInstanceProfile",
        "Namespace": "aws:autoscaling:launchconfiguration",
        "Value": "aws-elasticbeanstalk-ec2-role"
    },
    {
        "OptionName": "VPCId",
        "Namespace": "aws:ec2:vpc",
        "Value": vpc_id
    },
    {
        "OptionName": "Subnets",
        "Namespace": "aws:ec2:vpc",
        "Value": webserver_subnets
    },
    {
        "OptionName": "ELBSubnets",
        "Namespace": "aws:ec2:vpc",
        "Value": webserver_subnets
    },
    {
        "OptionName": "AssociatePublicIpAddress",
        "ResourceName": "AWSEBAutoScalingLaunchConfiguration",
        "Namespace": "aws:ec2:vpc",
        "Value": "true"
    },
    {
        "OptionName": "ELBScheme",
        "Namespace": "aws:ec2:vpc",
        "Value": "public"
    },
    {
        "OptionName": "Availability Zones",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:asg",
        "Value": "Any"
    },
    {
        "OptionName": "Cooldown",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:asg",
        "Value": cool_down
    },
    {
        "OptionName": "MaxSize",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:asg",
        "Value": autoscale_max_instance
    },
    {
        "OptionName": "MinSize",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:asg",
        "Value": autoscale_min_instance
    },
    {
        "OptionName": "BlockDeviceMappings",
        "ResourceName": "AWSEBAutoScalingLaunchConfiguration",
        "Namespace": "aws:autoscaling:launchconfiguration"
    },
    {
        "OptionName": "EC2KeyName",
        "ResourceName": "AWSEBAutoScalingLaunchConfiguration",
        "Namespace": "aws:autoscaling:launchconfiguration",
        "Value": ssh_key_name
    },
    {
        "OptionName": "IamInstanceProfile",
        "ResourceName": "AWSEBAutoScalingLaunchConfiguration",
        "Namespace": "aws:autoscaling:launchconfiguration",
        "Value": instance_profile
    },
    {
        "OptionName": "ServiceRole",
        "Namespace": "aws:elasticbeanstalk:environment",
        "Value": service_role
    },
    {
        "OptionName": "SSHSourceRestriction",
        "Namespace": "aws:autoscaling:launchconfiguration",
        "Value": ssh_restrictions
    },
    {
        "OptionName": "SecurityGroups",
        "ResourceName": "AWSEBAutoScalingLaunchConfiguration",
        "Namespace": "aws:autoscaling:launchconfiguration",
        "Value": instance_security_group
    },
    {
        "OptionName": "JDBC_CONNECTION_STRING",
        "Namespace": "aws:elasticbeanstalk:application:environment",
        "Value": ""
    },
    {
        "OptionName": "DeploymentPolicy",
        "Namespace": "aws:elasticbeanstalk:command",
        "Value": "Rolling"
    },
    {
        "OptionName": "LogPublicationControl",
        "Namespace": "aws:elasticbeanstalk:hostmanager",
        "Value": "true"
    },
    {
        "OptionName": "JVMOptions",
        "Namespace": "aws:cloudformation:template:parameter",
        "Value": "XX:MaxPermSize=64m,Xmx=256m,JVM Options=,Xms=256m"
    },
    {
        "OptionName": "BatchSize",
        "Namespace": "aws:elasticbeanstalk:command",
        "Value": rolling_update_batch_percent
    },
    {
        "OptionName": "BatchSizeType",
        "Namespace": "aws:elasticbeanstalk:command",
        "Value": "Percentage"
    },
    {
        "OptionName": "MinInstancesInService",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:updatepolicy:rollingupdate",
        "Value": "1"
    },
    {
        "OptionName": "JVM Options",
        "Namespace": "aws:elasticbeanstalk:container:tomcat:jvmoptions",
        "Value": ""
    },
    {
        "OptionName": "XX:MaxPermSize",
        "Namespace": "aws:elasticbeanstalk:container:tomcat:jvmoptions",
        "Value": "64m"
    },
    {
        "OptionName": "Xms",
        "Namespace": "aws:elasticbeanstalk:container:tomcat:jvmoptions",
        "Value": "256m"
    },
    {
        "OptionName": "Xmx",
        "Namespace": "aws:elasticbeanstalk:container:tomcat:jvmoptions",
        "Value": "256m"
    },
    {
        "OptionName": "PauseTime",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:updatepolicy:rollingupdate"
    },
    {
        "OptionName": "RollingUpdateEnabled",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:updatepolicy:rollingupdate",
        "Value": "true"
    },
    {
        "OptionName": "RollingUpdateType",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:updatepolicy:rollingupdate",
        "Value": "Health"
    },
    {
        "OptionName": "Timeout",
        "ResourceName": "AWSEBAutoScalingGroup",
        "Namespace": "aws:autoscaling:updatepolicy:rollingupdate",
        "Value": "PT30M"
    },
    {
        "OptionName": "HealthCheckSuccessThreshold",
        "Namespace": "aws:elasticbeanstalk:healthreporting:system",
        "Value": "Ok"
    },
    {
        "OptionName": "SystemType",
        "Namespace": "aws:elasticbeanstalk:healthreporting:system",
        "Value": "enhanced"
    },
    {
        "Namespace": "aws:autoscaling:launchconfiguration",
        "OptionName": "InstanceType",
        "Value": instance_type
    },
    {
        "OptionName": "CrossZone",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:loadbalancer",
        "Value": "true"
    },
    {
        "OptionName": "Application Healthcheck URL",
        "Namespace": "aws:elasticbeanstalk:application",
        "Value": healthcheck_url
    },
    {
        "OptionName": "HealthyThreshold",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:healthcheck",
        "Value": "3"
    },
    {
        "OptionName": "Interval",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:healthcheck",
        "Value": "10"
    },
    {
        "OptionName": "Notification Endpoint",
        "Namespace": "aws:elasticbeanstalk:sns:topics",
        "Value": notification_email
    },
    {
        "OptionName": "Notification Protocol",
        "Namespace": "aws:elasticbeanstalk:sns:topics",
        "Value": "email"
    },
    {
        "OptionName": "Target",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:healthcheck",
        "Value": "HTTP:80" + healthcheck_url
    },
    {
        "OptionName": "Timeout",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:healthcheck",
        "Value": "5"
    },
    {
        "OptionName": "UnhealthyThreshold",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:healthcheck",
        "Value": "5"
    },
    {
        "OptionName": "ConnectionDrainingEnabled",
        "ResourceName": "AWSEBLoadBalancer",
        "Namespace": "aws:elb:policies",
        "Value": "true"
    },
    {
        "OptionName": "ManagedActionsEnabled",
        "Namespace": "aws:elasticbeanstalk:managedactions",
        "Value": managed_actions_enabled
    },
    {
        "OptionName": "PreferredStartTime",
        "Namespace": "aws:elasticbeanstalk:managedactions",
        "Value": preferred_starttime
    },
    {
        "OptionName": "InstanceRefreshEnabled",
        "Namespace": "aws:elasticbeanstalk:managedactions:platformupdate",
        "Value": "false"
    },
    {
        "OptionName": "UpdateLevel",
        "Namespace": "aws:elasticbeanstalk:managedactions:platformupdate",
        "Value": update_level
    }
]
##############################

def get_secret(secret_name, endpoint_url, region_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error("The request had invalid params:", e)
    else:
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
            return binary_secret_data

def create_secret():
    key = RSA.generate(2048)
    logger.info("Private:\n{0}".format(key.exportKey('PEM')))

    pubkey = key.publickey()
    logger.info("Public:\n{0}".format(pubkey.exportKey('OpenSSH')))

    return key

def store_secret(secret_name, endpoint_url, region_name, kms_arn, vpc_id, payload, user_name):
    ssh_payload = {}
    ssh_payload['vpc_id'] = vpc_id
    ssh_payload['private'] = payload.exportKey('PEM')
    ssh_payload['public'] = payload.publickey().exportKey('OpenSSH')
    ssh_payload['user'] = user_name
    ssh_payload['version'] = str(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"))

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )
    try:
        create_secret_response = client.create_secret(
            Name = secret_name,
            KmsKeyId = kms_arn,
            SecretString = json.dumps(ssh_payload)
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            logger.error("Secret with name {0} already exist".format(secret_name))
        else:
            logger.error("Error: {0}".format(e.response))
    else:
        logger.info("Secret created {0}".format(create_secret_response['ARN']))
        return create_secret_response

def update_secret(secret_name, endpoint_url, region_name, kms_arn, vpc_id, payload, user_name):
    ssh_payload = {}
    ssh_payload['vpc_id'] = vpc_id
    ssh_payload['private'] = payload.exportKey('PEM')
    ssh_payload['public'] = payload.publickey().exportKey('OpenSSH')
    ssh_payload['user'] = user_name
    ssh_payload['version'] = str(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"))

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )
    try:
        update_secret_response = client.update_secret(
            SecretId=secret_name,
            KmsKeyId = kms_arn,
            SecretString = json.dumps(ssh_payload)
        )
    except ClientError as e:
        logger.error("Error: {0}".format(e.response))
        return False
    else:
        logger.info("Secret updated {0} version {1}".format(update_secret_response['ARN'], update_secret_response['VersionId']))
        return update_secret_response

def register_secret_in_cloud_insight(ci_client, secret_name, asset_type, asset_key, payload, user_name, cred_type, cred_sub_type):
    cred_payload = {}
    cred_payload["name"] = secret_name
    cred_payload["type"] = cred_type
    cred_payload["sub_type"] = cred_sub_type
    cred_payload["username"] = user_name
    cred_payload["key"] = str(payload["private"])
    response = ci_client.create_scan_credentials(asset_type = asset_type, asset_key = asset_key, payload = json.dumps(cred_payload))
    return response

def eb_check_dns_availability(eb_client, environment_name):
    response = eb_client.check_dns_availability(CNAMEPrefix=environment_name)
    if not response['Available']:
        logger.error("ERROR: Environment name: {0} already in use.".format(environment_name))
        return False
    else:
        logger.error("Environment name: {0} is available.".format(environment_name))
        return True

def eb_get_application_version(eb_client, application_name):
    response = eb_client.describe_application_versions(
        ApplicationName=application_name
    )
    if response['ApplicationVersions']:
        logger.error("Application name: {0} found {1} versions".format(application_name, len(response['ApplicationVersions'])))
        return response
    else:
        logger.error("Application name: {0} not found.".format(application_name))
        return False

def eb_create_application(eb_client, application_name):
    response = eb_client.describe_applications(ApplicationNames=[application_name])
    if not response['Applications'] or response['Applications'][0]['ApplicationName'] != application_name:
        response = eb_client.create_application(ApplicationName=application_name, Description=application_description)
        logger.info("EB Application created: {0}".format(response))
        return True
    else:
        logger.info("EB Application already exist: {0}".format(application_name))
        return False

def eb_create_config_template(eb_client, application_name, template_name, solution_stack, template_description, option_settings):
    response = eb_client.describe_applications(ApplicationNames=[application_name])
    if not template_name in response['Applications'][0]['ConfigurationTemplates']:
        response = eb_client.create_configuration_template(
            ApplicationName=application_name,
            TemplateName=template_name,
            SolutionStackName=solution_stack,
            Description=template_description,
            OptionSettings=option_settings
        )
        logger.info("EB Config template created: {0}".format(response))
        return True
    else:
        logger.info("EB Config template already exist: {0}".format(response))
        return False

def eb_update_config_template(eb_client, application_name, template_name, solution_stack, template_description, option_settings):
    response = eb_client.describe_applications(ApplicationNames=[application_name])
    if template_name in response['Applications'][0]['ConfigurationTemplates']:
        response = eb_client.update_configuration_template(
            ApplicationName=application_name,
            TemplateName=template_name,
            Description=template_description,
            OptionSettings=option_settings
        )
        logger.info("EB Config template updated: {0}".format(response))
        return True
    else:
        logger.info("EB Config template missing: {0}".format(response))
        return False

def eb_create_environment(eb_client, application_name, template_name, environment_name, environment_description):
    response = eb_client.create_environment(
        ApplicationName=application_name,
        EnvironmentName=environment_name,
        Description=environment_description,
        CNAMEPrefix=environment_name,
        Tier={
            'Name': 'WebServer',
            'Type': 'Standard'
        },
        Tags=[
            {
                'Key': 'name',
                'Value': environment_name
            },
        ],
        TemplateName=template_name
    )
    return response

def eb_get_environment(eb_client, application_name, environment_name):
    response = eb_client.describe_environments(
        ApplicationName=application_name,
        EnvironmentNames=[environment_name]
    )
    if response['Environments']:
        logger.info("Environment name: {0} found.".format(environment_name))
        return response
    else:
        logger.error("Environment name: {0} not found.".format(environment_name))
        return False

def eb_update_environment(eb_client, application_name, template_name, environment_id, environment_name, environment_description):
    response = eb_client.update_environment(
        ApplicationName=application_name,
        EnvironmentId=environment_id,
        EnvironmentName=environment_name,
        Description=environment_description,
        Tier={
            'Name': 'WebServer',
            'Type': 'Standard'
        },
        TemplateName=template_name,
    )
    return response

### Example from: https://github.com/coaic/eb-deployment-boto-scripts/blob/master/deploy_application_with_eb_api.py
class ProgressPercentage(object):
    def __init__(self, filename):
        self._filename = filename
        self._seen_so_far = 0
        self._lock = threading.Lock()
    def __call__(self, bytes_amount):
        # To simplify we'll assume this is hooked up
        # to a single filename.
        with self._lock:
            self._seen_so_far += bytes_amount
            sys.stdout.write(
                "\r%s --> %s bytes transferred\n" % (
                    self._filename, self._seen_so_far))
            sys.stdout.flush()

def eb_upload_application(eb_client, s3_client, application_file, application_version, application_name, environment_name, region, target_s3_bucket):
    zip_version =  "%s-%s" % (application_version, application_file)

    try:
        response = s3_client.head_bucket(Bucket=target_s3_bucket)
        logger.info("Found S3 bucket {0}".format(target_s3_bucket))
    except Exception as inst:
        logger.error("ERROR: S3 bucket {0} does not exist in region {1}" % (target_s3_bucket, region))
        exit(1)

    logger.info("Uploading application file: {0} to S3 bucket: {1}".format(application_file, target_s3_bucket))
    s3_client.upload_file(application_file, target_s3_bucket, zip_version, Callback=ProgressPercentage(zip_version))
    logger.info("Upload application file: {0} to S3 bucket: {1} complete - {2}".format(application_file, target_s3_bucket, zip_version))

    response = eb_client.create_application_version(
        ApplicationName=application_name,
        VersionLabel=application_version,
        Description=application_version,
        SourceBundle={
            'S3Bucket': target_s3_bucket,
            'S3Key': zip_version
        },
        AutoCreateApplication=False,
        Process=False
    )

    logger.info("Upload version: {0} to EB: {1} using file: {2}/{3}".format(application_version, application_name, target_s3_bucket, zip_version))

    response = eb_client.update_environment(
        EnvironmentName=environment_name,
        ApplicationName=application_name,
        VersionLabel=application_version
    )
    return response

if __name__ == '__main__':
    #Prepare parser and argument for cloud Insight related account and credentials
    parent_parser = argparse.ArgumentParser()
    required_parser = parent_parser.add_argument_group("Required arguments")
    required_parser.add_argument("--user", required=True, help="User name / email address for Insight API Authentication")
    required_parser.add_argument("--pswd", required=True, help="Password for Insight API Authentication")
    required_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")
    required_parser.add_argument("--cid", required=True, help="Target Alert Logic Customer ID for processing")
    required_parser.add_argument("--env", required=True, help="Target Alert Logic Cloud Insight Environment ID for processing")
    required_parser.add_argument("--mode", required=True, help="Set to ADD or REPLACE")
    parent_parser.add_argument("--log", help="Logging level, set to info, debug, error", default="info")

    try:
        args = parent_parser.parse_args()
    except:
        sys.exit(1)
    ops_mode = args.mode
    ci_args = {}
    if args.dc == "defender-us-denver":
        ci_args["yarp"] = "api.cloudinsight.alertlogic.com"
    elif args.dc == "defender-us-ashburn":
        ci_args["yarp"] = "api.cloudinsight.alertlogic.com"
    elif args.dc == "defender-uk-newport":
        ci_args["yarp"] = "api.cloudinsight.alertlogic.co.uk"

    ci_args["user"] = args.user
    ci_args["password"] = args.pswd
    ci_args["acc_id"] = args.cid
    ci_args["env_id"] = args.env
    ci_args["log_level"] = args.log

    if ops_mode == "REPLACE":
        #Load existing secret from AWS Secret Manager
        logger.info("\n{0} - START - Load secret from AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        response = get_secret(secret_name = secret_name, endpoint_url = endpoint_url, region_name = region_name)
        if response:
            keys = json.loads(response)
        else:
            sys.exit(1)
        logger.info("Secret Name: {0}".format(keys['vpc_id']))
        logger.info("Private Key: {0}".format(str(keys['private']).replace('\\n', '\n')))
        logger.info("Public Key: {0}".format(str(keys['public']).replace('\\n', '\n')))
        logger.info("{0} - END - Load secret from AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

        #Generate new SSH Key and update into AWS Secret Manager
        logger.info("\n{0} - START - Generate new SSH Key and update it in AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        payload = create_secret()
        update_secret( secret_name = secret_name, endpoint_url = endpoint_url, region_name = region_name, kms_arn = kms_arn, vpc_id = vpc_id, payload = payload, user_name = user_name)
        logger.info("{0} - END - Generate new SSH Key and update it in AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

        #store the public key as environment variable in EB option settings
        eb_option = {}
        eb_option["OptionName"] = "SSH_KEY"
        eb_option["Namespace"] = "aws:elasticbeanstalk:application:environment"
        #eb_option["Value"] = str(keys['public']).replace('\\n', '\n')
        eb_option["Value"] = payload.publickey().exportKey('OpenSSH')
        option_settings.append(eb_option)

        #Store SSH key to Cloud Insight as scan credentials
        logger.info("\n{0} - START - Update private key to Cloud Insight as scan credentials".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        myCI = al_ci_client.CloudInsight(ci_args)
        asset_type = "vpc"
        asset_key = "aws/us-west-2/vpc/vpc-d58792ac"
        cred_type = "ssh"
        cred_sub_type = "key"
        ci_secret_response = register_secret_in_cloud_insight(ci_client = myCI, secret_name = secret_name, asset_type = asset_type, asset_key = asset_key, payload = keys, user_name = user_name, cred_type = cred_type, cred_sub_type = cred_sub_type)
        if ci_secret_response:
            logger.info("Success : {0}".format(ci_secret_response))
        else:
            logger.error("Error : {0}".format(ci_secret_response))
        logger.info("{0} - END - Update private key to Cloud Insight as scan credentials\n".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

        #Update EB template
        logger.info("\n{0} - START - Update Elastic Beanstalk".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        eb_client = boto3.client('elasticbeanstalk', region)
        s3_client = boto3.client('s3', region)

        if eb_create_application(eb_client, application_name) == False:
            #Get the latest version and bump version 0.1
            response = eb_get_application_version(eb_client, application_name)
            application_version = response["ApplicationVersions"][0]['VersionLabel']
            for version in response["ApplicationVersions"]:
                if float(version['VersionLabel']) > application_version:
                    application_version = float(version['VersionLabel'])
            application_version = str(float(application_version) + 0.1)

            #Update template with the new environment variable value for SSH_KEY (public key)
            if eb_update_config_template(eb_client, application_name, template_name, solution_stack, template_description, option_settings):
                eb_environment = eb_get_environment(eb_client, application_name, environment_name)
                if eb_environment:
                    environment_id = eb_environment['Environments'][0]['EnvironmentId']
                    logger.info ("Update environment {0} id {1} with template {2}".format(environment_name, environment_id, template_name))
                    response = eb_update_environment(eb_client, application_name, template_name, environment_id, environment_name, environment_description)
                    healthy_environment = False
                    #
                    #  Wait for environment to become healthy
                    #
                    for __ in range(0, wait_for_green):
                        logger.info("Sleep 60 seconds and wait for EB environment {0} to become healthy".format(environment_id))
                        time.sleep(60)
                        response = eb_client.describe_environment_health(EnvironmentId=environment_id, AttributeNames=['Status'])
                        if response['Status'] == 'Ready':
                            healthy_environment = True
                            logger.info("Success EB environment {0} is healthy".format(environment_id))
                            break
                        else:
                            logger.info("EB environment {0} status: {1}".format(environment_id, response["Status"]))

                    if healthy_environment:
                        #Upload new app since ebextension take care of the replacement of the authorized keys
                        eb_upload_application(eb_client, s3_client, application_file, application_version, application_name, environment_name, region, target_s3_bucket)
                        #
                        #  Wait for environment to become healthy
                        #
                        for __ in range(0, wait_for_green):
                            logger.info("Sleep 60 seconds and wait for EB environment {0} to become healthy".format(environment_id))
                            time.sleep(60)
                            response = eb_client.describe_environment_health(EnvironmentId=environment_id, AttributeNames=['HealthStatus'])
                            if response['HealthStatus'] == 'Ok':
                                healthy_environment = True
                                logger.info("Success EB environment {0} is healthy".format(environment_id))
                                break
                            else:
                                logger.info("EB environment {0} health status: {1}".format(environment_id, response["HealthStatus"]))
                        logger.info("Demo completed")
                        exit(0)
                    else:
                        logger.error("ERROR: environment {0} failed to transition to healthy state".format(environment_name))
                        exit(1)

        logger.info("\n{0} - END - Update Elastic Beanstalk".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

    elif ops_mode == "ADD":
        #Generate new SSH Key and store in AWS Secret Manager
        logger.info("\n{0} - START - Generate new SSH Key and store it in AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        payload = create_secret()
        store_secret( secret_name = secret_name, endpoint_url = endpoint_url, region_name = region_name, kms_arn = kms_arn, vpc_id = vpc_id, payload = payload, user_name = user_name)
        logger.info("{0} - END - Generate new SSH Key and store it in AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

        #Load secret from AWS Secret Manager
        logger.info("\n{0} - START - Load secret from AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        keys = json.loads(get_secret(secret_name = secret_name, endpoint_url = endpoint_url, region_name = region_name))
        logger.info("Secret Name: {0}".format(keys['vpc_id']))
        logger.info("Private Key: {0}".format(str(keys['private']).replace('\\n', '\n')))
        logger.info("Public Key: {0}".format(str(keys['public']).replace('\\n', '\n')))
        logger.info("{0} - END - Load secret from AWS Secret Manager".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

        #store the public key as environment variable in EB option settings
        eb_option = {}
        eb_option["OptionName"] = "SSH_KEY"
        eb_option["Namespace"] = "aws:elasticbeanstalk:application:environment"
        eb_option["Value"] = str(keys['public']).replace('\\n', '\n')
        option_settings.append(eb_option)

        #Store SSH key to Cloud Insight as scan credentials
        logger.info("\n{0} - START - Insert private key to Cloud Insight as scan credentials".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        myCI = al_ci_client.CloudInsight(ci_args)
        asset_type = "vpc"
        asset_key = "aws/us-west-2/vpc/vpc-d58792ac"
        cred_type = "ssh"
        cred_sub_type = "key"
        ci_secret_response = register_secret_in_cloud_insight(ci_client = myCI, secret_name = secret_name, asset_type = asset_type, asset_key = asset_key, payload = keys, user_name = user_name, cred_type = cred_type, cred_sub_type = cred_sub_type)
        if ci_secret_response:
            logger.info("Success : {0}".format(ci_secret_response))
        else:
            logger.error("Error : {0}".format(ci_secret_response))
        logger.info("{0} - END - Insert private key to Cloud Insight as scan credentials\n".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))

        #Launch EB environment
        logger.info("\n{0} - START - Launch Elastic Beanstalk".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
        eb_client = boto3.client('elasticbeanstalk', region)
        s3_client = boto3.client('s3', region)

        if eb_check_dns_availability(eb_client, environment_name):
            if eb_create_application(eb_client, application_name):
                if eb_create_config_template(eb_client, application_name, template_name, solution_stack, template_description, option_settings):
                    response = eb_create_environment(eb_client, application_name, template_name, environment_name, environment_description)
                    if response:
                        logger.info("Environment launch start : {0}".format(response))
                        url = response['CNAME']
                        environment_id = response['EnvironmentId']
                        healthy_environment = False
                        #
                        #  Wait for environment to become healthy
                        #
                        for __ in range(0, wait_for_green):
                            logger.info("Sleep 60 seconds and wait for EB environment {0} to become healthy".format(environment_id))
                            time.sleep(60)
                            response = eb_client.describe_environment_health(EnvironmentId=environment_id, AttributeNames=['Status'])
                            if response['Status'] == 'Ready':
                                healthy_environment = True
                                logger.info("Success EB environment {0} is healthy".format(environment_id))
                                break
                            else:
                                logger.info("EB environment {0} status: {1}".format(environment_id, response["Status"]))

                        if healthy_environment:
                            eb_upload_application(eb_client, s3_client, application_file, application_version, application_name, environment_name, region, target_s3_bucket)
                            #
                            #  Wait for environment to become healthy
                            #
                            for __ in range(0, wait_for_green):
                                logger.info("Sleep 60 seconds and wait for EB environment {0} to become healthy".format(environment_id))
                                time.sleep(60)
                                response = eb_client.describe_environment_health(EnvironmentId=environment_id, AttributeNames=['HealthStatus'])
                                if response['HealthStatus'] == 'Ok':
                                    healthy_environment = True
                                    logger.info("Success EB environment {0} is healthy".format(environment_id))
                                    break
                                else:
                                    logger.info("EB environment {0} health status: {1}".format(environment_id, response["HealthStatus"]))
                            logger.info("Demo completed")
                            exit(0)
                        else:
                            logger.error("ERROR: environment {0} failed to transition to healthy state".format(environment_name))
                            exit(1)

        logger.info("{0} - END - Launch Elastic Beanstalk\n".format(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))))
