import collections
import datetime
import logging
import os
import boto3
from botocore.exceptions import ClientError
# test locally
# serverless invoke local -f create_snapshot -r us-west-2
# serverless invoke local -f copy_snapshot -r us-west-2

TAG_BK_ENALBED = os.environ.get('TagBkEnabled', 'SnapshotBackupEnabled')
TAG_BK_COPY_ENABLED = os.environ.get('TagCopyEnabled', 'SnapshotCopyEnabled')
DEST_REGION = os.environ.get('DRRegion', 'us-east-1')
BACKUP_RETENTION_DAYS = os.environ.get('SnapshotDefaultRetention', 7)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

def create_snapshots(ec2_client, instances):
    """Create snapshots and return list of tags to create."""
    to_tag = collections.defaultdict(list)
    for instance in instances:
        try:
            retention_days = [
                int(t.get('Value')) for t in instance['Tags']
                if t['Key'] == 'SnapshotRetention'][0]
        except IndexError:
            retention_days = int(BACKUP_RETENTION_DAYS)
        LOGGER.debug('Instance %s has %i days retention',
                     instance['InstanceId'],
                     retention_days)

        # Set flag dr_copy_enabled based on the tag TAG_BK_COPY_ENABLED             
        dr_copy_enabled = False
        for t in instance['Tags']:
            if t['Key'] == TAG_BK_COPY_ENABLED \
                and t.get('Value', '').lower() == 'true':
                dr_copy_enabled = True

        for dev in instance['BlockDeviceMappings']:
            if dev.get('Ebs', None) is None:
                continue
            vol_id = dev['Ebs']['VolumeId']
            LOGGER.info("Found EBS volume %s on instance %s",
                        vol_id,
                        instance['InstanceId'])
            snap = ec2_client.create_snapshot(
                VolumeId=vol_id,
            )
            LOGGER.debug('Created %s snapshot for instance %s',
                         snap['SnapshotId'],
                         instance['InstanceId'])
            # setting instance ID in array under the snapshot
            to_tag[snap['SnapshotId']].append(instance['InstanceId'])
            # setting the retention time period in array under the snapshot
            to_tag[snap['SnapshotId']].append(retention_days)
            # setting the instance name in the array under the snapshot
            instance_name = [
                str(t.get('Value')) for t in instance['Tags']
                if t['Key'] == 'Name'][0]
            to_tag[snap['SnapshotId']].append(instance_name)
            # setting the volume ID in array under the snapshot
            to_tag[snap['SnapshotId']].append(vol_id)
            to_tag[snap['SnapshotId']].append(dr_copy_enabled)
            LOGGER.debug("Retaining snapshot %s of volume %s "
                         "from instance %s for %d days",
                         snap['SnapshotId'],
                         vol_id,
                         instance['InstanceId'],
                         retention_days)
    return to_tag


def add_tags(ec2_client, tag_list):
    """Add tags to list of snapshots."""
    for snapshot in tag_list.keys():
        instanceid = tag_list[snapshot][0]
        retentiondaysforsnapshot = tag_list[snapshot][1]
        instance_name_tag = tag_list[snapshot][2]
        volume_id = tag_list[snapshot][3]
        dr_copy_enabled = tag_list[snapshot][4]
        delete_fmt = (
            datetime.datetime.now() +
            datetime.timedelta(days=retentiondaysforsnapshot)
        ).strftime('%Y-%m-%d-%H-%M')
        #print("Will delete snapshot for %s on %s" % (instanceid, delete_fmt))
        LOGGER.debug("Will delete snapshot for instance %s and volume %s "
                     "on %s",
                     instanceid,
                     volume_id,
                     delete_fmt)
        tags = [
                {'Key': 'DeleteOn', 'Value': delete_fmt},
                {'Key': 'Name', 'Value': "Automatic Backup of %s attached "
                                         " %s" % (volume_id,
                                                  str(instance_name_tag))},
                {'Key': 'InstanceID', 'Value': instanceid},                
            ]
        if dr_copy_enabled:
            tags.append({'Key': 'NeedToCopyToDr', 'Value': 'true'})
        ec2_client.create_tags(
            Resources=[snapshot],
            Tags=tags
        )
    return True

def delete_handler(event, context):  # pylint: disable=unused-argument
    """Delete expired snapshots.

    Looks at all snapshots that have a "DeleteOn" tag containing the current
    day formatted as YYYY-MM-DD. This function should be run at least daily.
    """
    myAccount = boto3.client('sts').get_caller_identity()['Account']
    current_time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')
    filters = [
        {'Name': 'tag-key', 'Values': ['DeleteOn']},
    ]
    my_session = boto3.session.Session()
    my_region = my_session.region_name

    ec2_client = boto3.client('ec2')

    snapshots = []
    des_snaps_paginator = ec2_client.get_paginator('describe_snapshots')
    des_snaps_iterator = des_snaps_paginator.paginate(OwnerIds=[myAccount],
                                                      Filters=filters)
    for page in des_snaps_iterator:
        if 'Snapshots' in page:
            snapshots.extend(page['Snapshots'])

    for snap in snapshots:
        for value in snap['Tags']:
            if value['Key'] == 'DeleteOn':
                LOGGER.debug('DeleteOn Tag Value: %s', value['Value'])
                if current_time > value['Value']:
                    LOGGER.info('Deleting snapshot %s', snap['SnapshotId'])
                    try:
                        ec2_client.delete_snapshot(
                            SnapshotId=snap['SnapshotId']
                        )
                    except ClientError as error:
                        LOGGER.error(error)
                        return False
    return True

def copy_handler(event, context):  # pylint: disable=unused-argument
    """Copy snapshots to DR Region.

    Looks at all snapshots that have a "NeedToCopyToDr" tag.
    If that value is true, copy over to DR Region
    and remove the tag after copy
    """
    myAccount = boto3.client('sts').get_caller_identity()['Account']
    current_time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')
    filters = [
        {'Name': 'tag-key', 'Values': ['NeedToCopyToDr']},
    ]
    my_session = boto3.session.Session()
    my_region = my_session.region_name

    ec2_client = boto3.client('ec2')

    snapshots = []
    des_snaps_paginator = ec2_client.get_paginator('describe_snapshots')
    des_snaps_iterator = des_snaps_paginator.paginate(OwnerIds=[myAccount],
                                                      Filters=filters)
    for page in des_snaps_iterator:
        if 'Snapshots' in page:
            snapshots.extend(page['Snapshots'])

    for snap in snapshots:
        for value in snap['Tags']:
            if value['Key'] == 'NeedToCopyToDr' \
               and value['Value'] == 'true' \
               and snap['State'] == 'completed':
                LOGGER.info('Copy snapshot(%s) to DR region (%s)'%(snap['SnapshotId'], DEST_REGION))
                try:
                    conn = boto3.client('ec2', region_name=DEST_REGION)
                    conn.copy_snapshot(
                        Description='DR backup from %s:%s'%(my_region,snap['SnapshotId']),
                        #Encrypted=True|False,
                        #KmsKeyId='string',
                        SourceRegion=my_region,
                        SourceSnapshotId=snap['SnapshotId'],
                        DestinationRegion=DEST_REGION,
                        DryRun=False
                    )
                    # delete tag after successful copy to DR region
                    LOGGER.info('Remove NeedToCopyToDr tag')

                    ret = ec2_client.delete_tags(
                        Resources=[snap['SnapshotId']],
                        Tags=[{'Key': 'NeedToCopyToDr' }]
                    );
                except Exception as e:
                    LOGGER.error(e)
                    return False
    return True
        

def handler(event, context):  # pylint: disable=unused-argument
    """Invoke create_snapshots & add_tags."""
    ec2_client = boto3.client('ec2')

    reservations = []
    des_inst_paginator = ec2_client.get_paginator('describe_instances')
    # des_inst_iterator = des_inst_paginator.paginate()
    des_inst_iterator = des_inst_paginator.paginate(Filters=[
        {'Name': 'tag:%s' % TAG_BK_ENALBED, 'Values': ['true']},
    ])
    for page in des_inst_iterator:
        if 'Reservations' in page:
            reservations.extend(page['Reservations'])
    instances = sum(
        [
            [i for i in r['Instances']]
            for r in reservations
        ], [])
    # for instance in instances:
    #     LOGGER.info(instance)
    LOGGER.info("Found %d instances that need backing up", len(instances))
    to_tag = create_snapshots(ec2_client, instances)
    add_tags(ec2_client, to_tag)
    LOGGER.info("Call delete_handler to check if any snapshot need to be deleted")
    delete_handler(event, context)
    return True
