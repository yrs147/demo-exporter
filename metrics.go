package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	totalVulnerabilities            prometheus.Gauge
	totalRCEVulnerabilities         prometheus.Gauge
	rceVulnerabilities              prometheus.GaugeVec
	totalFixableVulnerabilities     prometheus.Gauge
	fixableVulnerabilities          prometheus.GaugeVec
	totalImageVulnerabilities       prometheus.GaugeVec
	totalCriticalVulnerabilities    prometheus.Gauge
	criticalVulnerabilities         prometheus.GaugeVec
	totalHighVulnerabilities        prometheus.Gauge
	highVulnerabilities             prometheus.GaugeVec
	totalMediumVulnerabilities      prometheus.Gauge
	mediumVulnerabilities           prometheus.GaugeVec
	totalLowVulnerabilities         prometheus.Gauge
	lowVulnerabilities              prometheus.GaugeVec
	totalNegligibleVulnerabilities  prometheus.Gauge
	negligibleVulnerabilities       prometheus.GaugeVec
	totalUnknownVulnerabilities     prometheus.Gauge
	unknownVulnerabilities          prometheus.GaugeVec
}

var (
	totalVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_vulnerabilities",
		Help: "Total number of vulnerabilities in cluster",
	})
	totalRCEVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_rce_vulnerabilities",
		Help: "Total number of vulnerabilities related to remote code execution (RCE) in cluster",
	})
	rceVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rce_vulnerabilities",
		Help: "Number of vulnerabilities related to remote code execution (RCE) in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalFixableVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_fixable_vulnerabilities",
		Help: "Total number of fixable vulnerabilities in cluster",
	})
	fixableVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fixable_vulnerabilities",
		Help: "Number of fixable vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalImageVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "total_image_vulnerabilities",
		Help: "Total number of vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalCriticalVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_critical_vulnerabilities",
		Help: "Total number of critical vulnerabilities in cluster",
	})
	criticalVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "critical_vulnerabilities",
		Help: "Number of critical vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalHighVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_high_vulnerabilities",
		Help: "Total number of high vulnerabilities in cluster",
	})
	highVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "high_vulnerabilities",
		Help: "Number of high vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalMediumVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_medium_vulnerabilities",
		Help: "Total number of medium vulnerabilities in cluster",
	})
	mediumVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "medium_vulnerabilities",
		Help: "Number of medium vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalLowVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_low_vulnerabilities",
		Help: "Total number of low vulnerabilities in cluster",
	})
	lowVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "low_vulnerabilities",
		Help: "Number of low vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalNegligibleVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_negligible_vulnerabilities",
		Help: "Total number of negligible vulnerabilities in cluster",
	})
	negligibleVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "negligible_vulnerabilities",
		Help: "Number of negligible vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
	totalUnknownVulnerabilities = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_unknown_vulnerabilities",
		Help: "Total number of unknown vulnerabilities in cluster",
	})
	unknownVulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "unknown_vulnerabilities",
		Help: "Number of unknown vulnerabilities in image",
	}, []string{"name", "cluster", "namespace", "workload", "registry", "tag"})
)
