package provider

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	sakuraAPI "github.com/sacloud/libsacloud/api"
	"github.com/sacloud/libsacloud/sacloud"
	log "github.com/sirupsen/logrus"
)

const sakuraCloudRecordTTL = 300

// SakuraCloudProvider is an implementation of Provider for SakuraCloud's DNS.
type SakuraCloudProvider struct {
	Client       sakuraCloudDNSClient
	domainFilter DomainFilter
	DryRun       bool
}

// SakuraCloudChange differentiates between ChangActions
type SakuraCloudChange struct {
	Action            string
	ZoneID            int64
	Domain            string
	ResourceRecordSet sacloud.DNSRecordSet
}

type sakuraCloudDNSClient interface {
	find() ([]sacloud.DNS, error)
	update(int64, *sacloud.DNS) (*sacloud.DNS, error)
}

type defaultSakuraCloudClient struct {
	client *sakuraAPI.DNSAPI
}

func (d *defaultSakuraCloudClient) find() ([]sacloud.DNS, error) {
	d.client.Reset()
	d.client.SetLimit(1000)
	res, err := d.client.Find()
	if err != nil {
		return nil, err
	}

	return res.CommonServiceDNSItems, nil
}

func (d *defaultSakuraCloudClient) update(id int64, param *sacloud.DNS) (*sacloud.DNS, error) {
	return d.client.Update(id, param)
}

// NewSakuraCloudProvider initializes a new SakuraCloud DNS based Provider.
func NewSakuraCloudProvider(domainFilter DomainFilter, dryRun bool, appVersion string) (*SakuraCloudProvider, error) {
	token, ok := os.LookupEnv("SAKURACLOUD_ACCESS_TOKEN")
	if !ok {
		return nil, fmt.Errorf("No token found")
	}
	secret, ok := os.LookupEnv("SAKURACLOUD_ACCESS_TOKEN_SECRET")
	if !ok {
		return nil, fmt.Errorf("No secret found")
	}
	trace := false
	envtrace, ok := os.LookupEnv("SAKURACLOUD_TRACE_MODE")
	if ok && envtrace != "" {
		trace = true
	}

	apiClient := sakuraAPI.NewClient(token, secret, "is1a")
	apiClient.UserAgent = "external-dns+sakura-cloud/" + appVersion
	apiClient.TraceMode = trace

	provider := &SakuraCloudProvider{
		Client:       &defaultSakuraCloudClient{client: apiClient.DNS},
		domainFilter: domainFilter,
		DryRun:       dryRun,
	}
	return provider, nil
}

// Records returns the list of records in a given zone.
func (p *SakuraCloudProvider) Records() ([]*endpoint.Endpoint, error) {
	zones, err := p.Zones()
	if err != nil {
		return nil, err
	}
	var endpoints []*endpoint.Endpoint
	for _, zone := range zones {
		records := zone.Settings.DNS.ResourceRecordSets
		if err != nil {
			return nil, err
		}

		for _, r := range records {
			if supportedRecordType(r.Type) {
				name := r.Name + "." + zone.Name

				// root name is identified by @ and should be
				// translated to zone name for the endpoint entry.
				if r.Name == "@" {
					name = zone.Name
				}

				// is already exists with same name and type?
				var existsEndPoint *endpoint.Endpoint
				for _, ep := range endpoints {
					if ep.DNSName == name && ep.RecordType == r.Type {
						existsEndPoint = ep
						break
					}
				}

				if existsEndPoint == nil {
					endpoints = append(endpoints, endpoint.NewEndpointWithTTL(name, r.Type, endpoint.TTL(r.TTL), r.RData))
				} else {
					existsEndPoint.Targets = append(existsEndPoint.Targets, r.RData)
				}
			}
		}
	}

	return endpoints, nil
}

// Zones returns the list of hosted zones.
func (p *SakuraCloudProvider) Zones() ([]*sacloud.DNS, error) {
	var result []*sacloud.DNS
	zones, err := p.Client.find()
	if err != nil {
		return nil, err
	}

	for _, zone := range zones {
		if p.domainFilter.Match(zone.Name) {
			result = append(result, &zone)
		}
	}

	return result, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *SakuraCloudProvider) ApplyChanges(changes *plan.Changes) error {
	zones, err := p.Zones()

	if err != nil {
		return err
	}

	zonesByID := make(map[string]*sacloud.DNS)

	zoneNameIDMapper := zoneIDName{}

	for _, z := range zones {
		zoneID := z.GetStrID()
		zoneNameIDMapper.Add(zoneID, z.Name)
		zonesByID[zoneID] = z
	}

	addRecordActions := []map[string][]*endpoint.Endpoint{
		p.endpointsByZone(zoneNameIDMapper, changes.Create),
		p.endpointsByZone(zoneNameIDMapper, changes.UpdateNew),
	}

	removeRecordActions := []map[string][]*endpoint.Endpoint{
		p.endpointsByZone(zoneNameIDMapper, changes.UpdateOld),
		p.endpointsByZone(zoneNameIDMapper, changes.Delete),
	}

	// for debug log
	allChanges := map[string][]*endpoint.Endpoint{
		"create":    changes.Create,
		"updateOld": changes.UpdateOld,
		"updateNew": changes.UpdateNew,
		"delete":    changes.Delete,
	}
	for k, v := range allChanges {
		for _, ep := range v {
			log.Debugf("SakuraCloud: %s: %#v", k, ep)
		}
	}

	// Generate Creates/Updates
	for _, targets := range addRecordActions {
		for zoneID, creates := range targets {
			zone := zonesByID[zoneID]

			if len(creates) == 0 {
				log.WithFields(log.Fields{
					"zoneID":   zoneID,
					"zoneName": zone.Name,
				}).Debug("Skipping Zone, no creates/updates found.")
				continue
			}

			for _, ep := range creates {
				records := p.endpointToRecord(zone, ep)
				for _, record := range records {
					zone.AddRecord(record)
				}
			}
		}
	}

	// Generate UpdatesOld/Deletes
	for _, targets := range removeRecordActions {
		for zoneID, updates := range targets {
			zone := zonesByID[zoneID]

			if len(updates) == 0 {
				log.WithFields(log.Fields{
					"zoneID":   zoneID,
					"zoneName": zone.Name,
				}).Debug("Skipping Zone, no updatesOld/delete found.")
				continue
			}

			for _, ep := range updates {
				p.removeRecord(zone, ep)
			}
		}
	}

	if p.DryRun {
		return nil
	}

	// update SakuraCloud Records
	for _, zone := range zonesByID {
		if _, err := p.Client.update(zone.ID, zone); err != nil {
			return err
		}
	}

	return nil
}

func (p *SakuraCloudProvider) endpointsByZone(zoneNameIDMapper zoneIDName, endpoints []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	endpointsByZone := make(map[string][]*endpoint.Endpoint)

	for _, ep := range endpoints {
		zoneID, _ := zoneNameIDMapper.FindZone(ep.DNSName)
		if zoneID == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected ", ep.DNSName)
			continue
		}
		endpointsByZone[zoneID] = append(endpointsByZone[zoneID], ep)
	}

	return endpointsByZone
}

func (p *SakuraCloudProvider) endpointToRecord(zone *sacloud.DNS, ep *endpoint.Endpoint) []*sacloud.DNSRecordSet {
	var res []*sacloud.DNSRecordSet

	// no annotation results in a TTL of 0, default to 300 for consistency with other providers
	var ttl = sakuraCloudRecordTTL
	if ep.RecordTTL.IsConfigured() {
		ttl = int(ep.RecordTTL)
	}

	for _, rdata := range ep.Targets {
		// if rdata is surrounded with double quote, strip it.
		rdata = strings.TrimPrefix(rdata, `"`)
		rdata = strings.TrimSuffix(rdata, `"`)

		res = append(res, &sacloud.DNSRecordSet{
			Name:  p.getStrippedRecordName(zone, ep),
			Type:  ep.RecordType,
			RData: rdata,
			TTL:   ttl,
		})
	}
	return res
}

func (p *SakuraCloudProvider) removeRecord(zone *sacloud.DNS, ep *endpoint.Endpoint) {
	recordSets := zone.Settings.DNS.ResourceRecordSets
	targets := p.endpointToRecord(zone, ep)

	for _, target := range targets {
		recordSets = p.removeRecordFromRecordSets(recordSets, target)
	}

	zone.Settings.DNS.ResourceRecordSets = recordSets
}

func (p *SakuraCloudProvider) removeRecordFromRecordSets(records []sacloud.DNSRecordSet, target *sacloud.DNSRecordSet) []sacloud.DNSRecordSet {
	results := []sacloud.DNSRecordSet{}
	for _, r := range records {
		if !(r.Type == target.Type && r.RData == target.RData && r.Name == target.Name && r.TTL == target.TTL) {
			results = append(results, r)
		}
	}
	return results
}

func (p *SakuraCloudProvider) getStrippedRecordName(zone *sacloud.DNS, ep *endpoint.Endpoint) string {
	// Handle root
	if ep.DNSName == zone.Name {
		return "@"
	}

	return strings.TrimSuffix(ep.DNSName, "."+zone.Name)
}
