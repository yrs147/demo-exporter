package main

type Vulnerability struct{
	Name 			string 		`json:"name"`
	Components		string 		`json:"components"`
	Severity		string 		`json:"severity"`
	Fixable			string 		`json:"fixable"`
	FixInVersion	string 		`json:"fix_in_version"`
	RCE				string 		`json:"rce"`
	Description		string 		`json:"description"`

}

type Item struct {
	Cluster 		string				`json:"cluster"`
	Namespace    	string				`json:"namespace"`
	Workload		string				`json:"workload"`
	Container		string				`json:"container"`
	Registry		string				`json:"registry"`
	Tag				string				`json:"tag"`
	Vulnerability	[]Vulnerability		`json:"vulnerabilities"`
}

