# Setting up ExternalDNS for Services on SakuraCloud

This tutorial describes how to setup ExternalDNS for usage within a Kubernetes cluster using SakuraCloud DNS.

## Creating a SakuraCloud DNS zone

Create a new DNS zone where you want to create your records in. Let's use `example.com` as an example here.

## Creating SakuraCloud Credentials

Generate a new API keys by going to [the API settings](https://secure.sakura.ad.jp/cloud/?#!/apikey/top/) or follow [Manuals for using SakuraCloud's API Key](https://manual.sakura.ad.jp/cloud/api/apikey.html) if you need more information. 
Give the API Key a name and allow `edit` operations. The API Key needs to be passed to ExternalDNS so make a note of it for later use.

The environment variable `SAKURACLOUD_ACCESS_TOKEN` and `SAKURACLOUD_ACCESS_TOKEN_SECRET` will be needed to run ExternalDNS with SakuraCloud.

## Deploy ExternalDNS

Connect your `kubectl` client to the cluster you want to test ExternalDNS with.
Then apply one of the following manifests file to deploy ExternalDNS.

### Manifest (for clusters without RBAC enabled)
```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: external-dns
spec:
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      containers:
      - name: external-dns
        image: sacloud/external-dns:latest
        args:
        - --source=service 
        - --source=ingress
        - --domain-filter=example.com # (optional, but we highly recommended to set this) limit to only example.com domains; change to match the zone created above.
        - --provider=sakuracloud
        env:
        - name: SAKURACLOUD_ACCESS_TOKEN
          value: "YOUR_API_KEY"
        - name: SAKURACLOUD_ACCESS_TOKEN_SECRET
          value: "YOUR_API_SECRET"
```

### Manifest (for clusters with RBAC enabled)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-dns
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: external-dns
rules:
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get","watch","list"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get","watch","list"]
- apiGroups: ["extensions"] 
  resources: ["ingresses"] 
  verbs: ["get","watch","list"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: external-dns-viewer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: external-dns
subjects:
- kind: ServiceAccount
  name: external-dns
  namespace: default
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: external-dns
spec:
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
      - name: external-dns
        image: sacloud/external-dns:latest
        args:
        - --source=service 
        - --source=ingress
        - --domain-filter=example.com # (optional, but we highly recommended to set this) limit to only example.com domains; change to match the zone created above.
        - --provider=sakuracloud
        env:
        - name: SAKURACLOUD_ACCESS_TOKEN
          value: "YOUR_API_KEY"
        - name: SAKURACLOUD_ACCESS_TOKEN_SECRET
          value: "YOUR_API_SECRET"
```


## Deploying an Nginx Service

Create a service file called 'nginx.yaml' with the following contents:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx
spec:
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    external-dns.alpha.kubernetes.io/hostname: my-app.example.com
spec:
  selector:
    app: nginx
  type: LoadBalancer
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
```

Note the annotation on the service; use the same hostname as the SakuraCloud DNS zone created above.

ExternalDNS uses this annotation to determine what services should be registered with DNS. Removing the annotation will cause ExternalDNS to remove the corresponding DNS records.

Create the deployment and service:

```console
$ kubectl create -f nginx.yaml
```

Depending where you run your service it can take a little while for your cloud provider to create an external IP for the service.

Once the service has an external IP assigned, ExternalDNS will notice the new service IP address and synchronize the SakuraCloud DNS records.

## Verifying SakuraCloud DNS records

Check your [SakuraCloud' Control Panel](https://secure.sakura.ad.jp/cloud/iaas/#!/appliance/dns/) to view the records for your SakuraCloud DNS zone.

Click on the zone for the one created above if a different domain was used.

This should show the external IP address of the service as the A record for your domain.

## Cleanup

Now that we have verified that ExternalDNS will automatically manage SakuraCloud DNS records, we can delete the tutorial's example:

```
$ kubectl delete service -f nginx.yaml
$ kubectl delete service -f externaldns.yaml
```
