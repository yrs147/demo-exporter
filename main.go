package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Vulnerability struct {
	Name         string `json:"name"`
	Components   string `json:"components"`
	Severity     string `json:"severity"`
	Fixable      string `json:"fixable"`
	FixInVersion string `json:"fix_in_version"`
	RCE          string `json:"rce"`
	Description  string `json:"description"`
}

type Item struct {
	Cluster         string          `json:"cluster"`
	Namespace       string          `json:"namespace"`
	Workload        string          `json:"workload"`
	Container       string          `json:"container"`
	Registry        string          `json:"registry"`
	Tag             string          `json:"tag"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}



type Metrics struct {
	total_vulnerabilities      prometheus.GaugeVec
	rce_vulnerabilities        prometheus.GaugeVec
	fixable_vulnerabilities    prometheus.GaugeVec
	critical_vulnerabilities   prometheus.GaugeVec
	high_vulnerabilities       prometheus.GaugeVec
	medium_vulnerabilities     prometheus.GaugeVec
	low_vulnerabilities        prometheus.GaugeVec
	negligible_vulnerabilities prometheus.GaugeVec
	unknown_vulnerabilities    prometheus.GaugeVec
}

var (
	total_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "total_vulnerabilities",
		Help: "Total number of vulnerabilities in cluster",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	rce_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rce_vulnerabilities",
		Help: "Number of vulnerabilities related to remote code execution (RCE) in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	fixable_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fixable_vulnerabilities",
		Help: "Number of fixable vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	critical_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "critical_vulnerabilities",
		Help: "Number of critical vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	high_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "high_vulnerabilities",
		Help: "Number of high vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	medium_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "medium_vulnerabilities",
		Help: "Number of medium vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	low_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "low_vulnerabilities",
		Help: "Number of low vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	negligible_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "negligible_vulnerabilities",
		Help: "Number of negligible vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
	unknown_vulnerabilities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "unknown_vulnerabilities",
		Help: "Number of unknown vulnerabilities in image",
	}, []string{"cluster", "namespace", "workload", "registry", "tag"})
)

func init() {

	prometheus.MustRegister(total_vulnerabilities)
	prometheus.MustRegister(rce_vulnerabilities)
	prometheus.MustRegister(fixable_vulnerabilities)
	prometheus.MustRegister(critical_vulnerabilities)
	prometheus.MustRegister(high_vulnerabilities)
	prometheus.MustRegister(medium_vulnerabilities)
	prometheus.MustRegister(low_vulnerabilities)
	prometheus.MustRegister(negligible_vulnerabilities)
	prometheus.MustRegister(unknown_vulnerabilities)

}

func main() {

	// Process the metrics
	total, neg, high, med, low, crit, fix, rce, unk := ProcessMetrics()

	fmt.Println("=====Metrics Report==========")
	fmt.Println("Total Vulnerabilities: ", total)
	fmt.Println("Negligible Vulnerabilities: ", neg)
	fmt.Println("High Vulnerabilities: ", high)
	fmt.Println("Medium Vulnerabilities: ", med)
	fmt.Println("Low Vulnerabilities: ", low)
	fmt.Println("Critical Vulnerabilities: ", crit)
	fmt.Println("Fix Vulnerabilities: ", fix)
	fmt.Println("RCE Vulnerabilities: ", rce)
	fmt.Println("Unknown Vulnerabilities: ", unk)

	// Start the Prometheus HTTP handler
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))

}

func ProcessMetrics() (total int, neg int, high int, med int, low int, crit int, fix int, rce int, unk int) {
	output, err := ioutil.ReadFile("sample.json")
	if err != nil {
		panic(err)
	}

	// Unmarshal
	var items []Item
	err = json.Unmarshal(output, &items)
	if err != nil {
		panic(err)
	}

	totalVulnerabilities := 0
	rceVulnerabilities := 0
	fixableVulnerabilities := 0
	criticalVulnerabilities := 0
	highVulnerabilities := 0
	mediumVulnerabilities := 0
	lowVulnerabilities := 0
	negligibleVulnerabilities := 0
	unknownVulnerabilities := 0

	for _, item := range items {
		totalVulnerabilities += len(item.Vulnerabilities)

		for _, vuln := range item.Vulnerabilities {
			switch vuln.Severity {
			case "Critical":
				criticalVulnerabilities++
			case "High":
				highVulnerabilities++
			case "Medium":
				mediumVulnerabilities++
			case "Low":
				lowVulnerabilities++
			case "Negligible":
				negligibleVulnerabilities++
			default:
				unknownVulnerabilities++
			}

			if vuln.Fixable == "Yes" {
				fixableVulnerabilities++
			}

			if vuln.RCE == "Yes" {
				rceVulnerabilities++
			}
			// Update Prometheus metrics with labels
			total_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(totalVulnerabilities))
			rce_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(rceVulnerabilities))
			fixable_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(fixableVulnerabilities))
			critical_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(criticalVulnerabilities))
			high_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(highVulnerabilities))
			medium_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(mediumVulnerabilities))
			low_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(lowVulnerabilities))
			negligible_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(negligibleVulnerabilities))
			unknown_vulnerabilities.WithLabelValues(item.Cluster, item.Namespace, item.Workload, item.Registry, item.Tag).Set(float64(unknownVulnerabilities))
		}
	}

	return totalVulnerabilities, negligibleVulnerabilities, highVulnerabilities, mediumVulnerabilities, lowVulnerabilities, criticalVulnerabilities, fixableVulnerabilities, rceVulnerabilities, unknownVulnerabilities
}
