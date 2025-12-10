package detection

import (
	"net/http"
	"strings"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func DetectCDN(headers http.Header) types.CDNInfo {
	cdn := types.CDNInfo{}
	cdnSignatures := map[string][]string{
		"Cloudflare":   {"CF-Ray", "CF-Cache-Status", "__cfduid"},
		"CloudFront":   {"X-Amz-Cf-Id", "X-Amz-Cf-Pop", "X-Cache"},
		"Fastly":       {"Fastly-Debug-Digest", "X-Fastly-Request-ID"},
		"Akamai":       {"X-Akamai-Transformed", "Akamai-Origin-Hop"},
		"Azure CDN":    {"X-Azure-Ref", "X-EC-Debug"},
		"Incapsula":    {"X-Iinfo", "X-CDN"},
		"KeyCDN":       {"X-Edge-Location"},
		"StackPath":    {"X-Sp-Cache"},
		"BunnyCDN":     {"Bunny-Cache-Status"},
		"Google Cloud": {"X-Goog-Generation"},
	}

	for provider, headerKeys := range cdnSignatures {
		for _, key := range headerKeys {
			if headers.Get(key) != "" {
				cdn.Detected = true
				cdn.Provider = provider
				cdn.Headers = append(cdn.Headers, key+": "+headers.Get(key))
				return cdn
			}
		}
	}

	if via := headers.Get("Via"); via != "" {
		via = strings.ToLower(via)
		if strings.Contains(via, "varnish") {
			cdn.Detected = true
			cdn.Provider = "Varnish Cache"
			cdn.Headers = append(cdn.Headers, "Via: "+headers.Get("Via"))
		} else if strings.Contains(via, "cloudflare") {
			cdn.Detected = true
			cdn.Provider = "Cloudflare"
			cdn.Headers = append(cdn.Headers, "Via: "+headers.Get("Via"))
		}
	}
	return cdn
}

func DetectServiceMesh(headers http.Header) types.ServiceMeshInfo {
	mesh := types.ServiceMeshInfo{}

	if serverHeader := headers.Get("Server"); strings.Contains(strings.ToLower(serverHeader), "istio") {
		mesh.Detected = true
		mesh.Type = "Istio"
		if version := headers.Get("X-Envoy-Upstream-Service-Time"); version != "" {
			mesh.Headers = append(mesh.Headers, "X-Envoy-Upstream-Service-Time: "+version)
		}
	}

	if envoyVersion := headers.Get("X-Envoy-Decorator-Operation"); envoyVersion != "" {
		mesh.Detected = true
		if mesh.Type == "" {
			mesh.Type = "Envoy Proxy"
		}
		mesh.Headers = append(mesh.Headers, "X-Envoy-Decorator-Operation: "+envoyVersion)
	}
	if envoyUpstream := headers.Get("X-Envoy-Upstream-Service-Time"); envoyUpstream != "" {
		if !mesh.Detected {
			mesh.Detected = true
			mesh.Type = "Envoy Proxy"
		}
		mesh.Headers = append(mesh.Headers, "X-Envoy-Upstream-Service-Time: "+envoyUpstream)
	}

	if linkerdVersion := headers.Get("L5d-Server-Id"); linkerdVersion != "" {
		mesh.Detected = true
		mesh.Type = "Linkerd"
		mesh.Version = linkerdVersion
		mesh.Headers = append(mesh.Headers, "L5d-Server-Id: "+linkerdVersion)
	}
	if linkerdCtx := headers.Get("L5d-Ctx-Trace"); linkerdCtx != "" {
		if !mesh.Detected {
			mesh.Detected = true
			mesh.Type = "Linkerd"
		}
		mesh.TraceID = linkerdCtx
		mesh.Headers = append(mesh.Headers, "L5d-Ctx-Trace: "+linkerdCtx)
	}

	if consulHeader := headers.Get("X-Consul-Effective-Consistency"); consulHeader != "" {
		mesh.Detected = true
		mesh.Type = "Consul Connect"
		mesh.Headers = append(mesh.Headers, "X-Consul-Effective-Consistency: "+consulHeader)
	}

	if appmeshHeader := headers.Get("X-Amzn-Request-Id"); appmeshHeader != "" {
		if envoyUpstream := headers.Get("X-Envoy-Upstream-Service-Time"); envoyUpstream != "" {
			mesh.Detected = true
			mesh.Type = "AWS App Mesh"
			mesh.Headers = append(mesh.Headers, "X-Amzn-Request-Id: "+appmeshHeader)
		}
	}

	if kumaHeader := headers.Get("Kuma-Revision"); kumaHeader != "" {
		mesh.Detected = true
		mesh.Type = "Kuma"
		mesh.Version = kumaHeader
		mesh.Headers = append(mesh.Headers, "Kuma-Revision: "+kumaHeader)
	}

	if traceParent := headers.Get("Traceparent"); traceParent != "" && mesh.TraceID == "" {
		mesh.TraceID = traceParent
	}
	if b3TraceId := headers.Get("X-B3-Traceid"); b3TraceId != "" && mesh.TraceID == "" {
		mesh.TraceID = b3TraceId
	}
	return mesh
}

func DetectLoadBalancer(headers http.Header) types.LoadBalancerInfo {
	lb := types.LoadBalancerInfo{}

	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "nginx") {
		if upstreamAddr := headers.Get("X-Upstream-Addr"); upstreamAddr != "" {
			lb.Detected = true
			lb.Type = "NGINX"
			lb.Backend = upstreamAddr
			lb.Headers = append(lb.Headers, "X-Upstream-Addr: "+upstreamAddr)
		}
		if upstreamStatus := headers.Get("X-Upstream-Status"); upstreamStatus != "" {
			if !lb.Detected {
				lb.Detected = true
				lb.Type = "NGINX"
			}
			lb.Headers = append(lb.Headers, "X-Upstream-Status: "+upstreamStatus)
		}
	}

	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "haproxy") {
		lb.Detected = true
		lb.Type = "HAProxy"
	}

	if elbHeader := headers.Get("X-Amzn-Trace-Id"); elbHeader != "" {
		lb.Detected = true
		lb.Type = "AWS Load Balancer"
		lb.Headers = append(lb.Headers, "X-Amzn-Trace-Id: "+elbHeader)
	}
	if albHeader := headers.Get("X-Amzn-Request-Id"); albHeader != "" && !lb.Detected {
		lb.Detected = true
		lb.Type = "AWS Application Load Balancer"
		lb.Headers = append(lb.Headers, "X-Amzn-Request-Id: "+albHeader)
	}

	if gclbHeader := headers.Get("Via"); strings.Contains(strings.ToLower(gclbHeader), "google") {
		lb.Detected = true
		lb.Type = "Google Cloud Load Balancer"
		lb.Headers = append(lb.Headers, "Via: "+gclbHeader)
	}

	if azureHeader := headers.Get("X-Azure-Ref"); azureHeader != "" {
		lb.Detected = true
		lb.Type = "Azure Load Balancer"
		lb.Headers = append(lb.Headers, "X-Azure-Ref: "+azureHeader)
	}

	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "traefik") {
		lb.Detected = true
		lb.Type = "Traefik"
	}
	return lb
}

func DetectContainerEnvironment(headers http.Header, dnsInfo types.DNSInfo) types.ContainerInfo {
	container := types.ContainerInfo{}

	if ingressClass := headers.Get("X-Ingress-Controller"); ingressClass != "" {
		container.Detected = true
		container.Orchestrator = "Kubernetes"
		container.Ingress = ingressClass
		container.Headers = append(container.Headers, "X-Ingress-Controller: "+ingressClass)
	}

	if nginxIngress := headers.Get("X-Request-Id"); nginxIngress != "" {
		if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "nginx") {
			container.Detected = true
			container.Orchestrator = "Kubernetes"
			container.Ingress = "NGINX Ingress Controller"
		}
	}

	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "traefik") {
		container.Detected = true
		container.Orchestrator = "Kubernetes"
		container.Ingress = "Traefik"
	}

	if contourHeader := headers.Get("X-Contour-Version"); contourHeader != "" {
		container.Detected = true
		container.Orchestrator = "Kubernetes"
		container.Ingress = "Contour"
		container.Headers = append(container.Headers, "X-Contour-Version: "+contourHeader)
	}

	for _, ns := range dnsInfo.NS {
		nsLower := strings.ToLower(ns)
		if strings.Contains(nsLower, "k8s") || strings.Contains(nsLower, "kubernetes") {
			container.Detected = true
			container.Orchestrator = "Kubernetes"
		}
	}

	if dockerHeader := headers.Get("Docker-Distribution-Api-Version"); dockerHeader != "" {
		container.Detected = true
		container.Registry = "Docker Registry"
		container.Headers = append(container.Headers, "Docker-Distribution-Api-Version: "+dockerHeader)
	}
	if harborHeader := headers.Get("X-Harbor-Version"); harborHeader != "" {
		container.Detected = true
		container.Registry = "Harbor Registry"
		container.Headers = append(container.Headers, "X-Harbor-Version: "+harborHeader)
	}

	if server := headers.Get("Server"); server != "" {
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "openshift") {
			container.Detected = true
			container.Platform = "OpenShift"
			container.Orchestrator = "Kubernetes"
		} else if strings.Contains(serverLower, "rancher") {
			container.Detected = true
			container.Platform = "Rancher"
			container.Orchestrator = "Kubernetes"
		}
	}
	return container
}

func DetectCloudProvider(headers http.Header, geoInfo []types.GeoInfo) types.CloudProviderInfo {
	cloud := types.CloudProviderInfo{}

	if headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "" {
		cloud.Provider = "AWS"
		cloud.Service = append(cloud.Service, "CloudFront")
		if cfPop := headers.Get("X-Amz-Cf-Pop"); cfPop != "" {
			cloud.Region = cfPop
			cloud.Headers = append(cloud.Headers, "X-Amz-Cf-Pop: "+cfPop)
		}
	}
	if headers.Get("X-Amzn-Request-Id") != "" || headers.Get("X-Amzn-Trace-Id") != "" {
		if cloud.Provider == "" {
			cloud.Provider = "AWS"
		}
		if !contains(cloud.Service, "Elastic Load Balancer") {
			cloud.Service = append(cloud.Service, "Elastic Load Balancer")
		}
	}

	if gfeHeader := headers.Get("Server"); strings.Contains(strings.ToLower(gfeHeader), "gfe") {
		cloud.Provider = "Google Cloud Platform"
		cloud.Service = append(cloud.Service, "Google Frontend")
	}
	if headers.Get("X-Goog-Generation") != "" || headers.Get("X-Goog-Stored-Content-Length") != "" {
		if cloud.Provider == "" {
			cloud.Provider = "Google Cloud Platform"
		}
		cloud.Service = append(cloud.Service, "Cloud Storage")
	}

	if headers.Get("X-Azure-Ref") != "" {
		cloud.Provider = "Microsoft Azure"
		cloud.Service = append(cloud.Service, "Azure CDN")
		if azureRef := headers.Get("X-Azure-Ref"); azureRef != "" {
			cloud.Headers = append(cloud.Headers, "X-Azure-Ref: "+azureRef)
		}
	}
	if headers.Get("X-Ms-Request-Id") != "" {
		if cloud.Provider == "" {
			cloud.Provider = "Microsoft Azure"
		}
		cloud.Service = append(cloud.Service, "Azure Service")
	}

	if len(geoInfo) > 0 {
		org := strings.ToLower(geoInfo[0].Organization)
		if strings.Contains(org, "digitalocean") {
			cloud.Provider = "DigitalOcean"
		} else if strings.Contains(org, "oracle") {
			cloud.Provider = "Oracle Cloud"
		} else if strings.Contains(org, "alibaba") {
			cloud.Provider = "Alibaba Cloud"
		}
	}
	return cloud
}
