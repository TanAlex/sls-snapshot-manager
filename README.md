# EC2 snapshot manager 

This tool creates 2 lambdas (all in one single python code).  
One lambda is triggered every 1 hour to backup any instances which have a tag  
`SnapshotBackupEnabled: true` 

It will tag the new snapshot with a few tags  
* InstanceId: the EC2 InstanceId this snapshot was taken from
* NeedToCopyToDr: true
* DeleteOn: the date time this snapshot will be deleted

This lambda will only add `NeedToCopyToDr: true` if the original instance has a tag `SnapshotCopyEnabled: true` otherwise this `NeedToCopyToDr` tag won't be added  

This lambda will also check all existing snapshots to see if any of them have  
`DeleteOn` datetime earlier than current date. if it finds them, those snapshots will be removed.

The other lambda will be triggered every 5 minutes to check if any Snapshots have `SnapshotCopyEnabled: true` tag and the snapshot's status is "completed".

It will then copy those snapshots to the DRRegion (Disaster Recovery Region) in same account. After successfully copy the snapshot, it will remove the tage `snapshotCopyEnabled` so that snapshot won't be copied again in next run.

## Custom behaviour by environment variables

Those variables are controlled in `serverless.yml` file
Example is showing down below

```
custom:
  DRRegion:
    local: us-east-1
    dev: us-east-2
    prod: us-east-2
  SnapshotDefaultRetention: 
    local: 1
    dev: 1
    prod: 7
```

## Test and deploy

Test

```
cd snapshot_mgr.sls
# serverless invoke local -f create_snapshot -r us-west-2
# serverless invoke local -f copy_snapshot -r us-west-2
```

Deploy to Dev

```
pipenv sync
pipenv shell
DEPLOY_ENVIRONMENT=dev runway deploy
```
or simply

```
cd snapshot_mgr.sls
sls deploy -r us-west-2 --stage dev
```
