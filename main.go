package main

import (
	"encoding/json"
	"io/ioutil"
)

func main(){
	
	output,err := ioutil.ReadFile("output.json")
	if err!=nil{
		panic(err)
	}

	//Unmarshal
	var items []Item
	err = json.Unmarshal(output,&items)
	if err!=nil{
		panic(err)
	}


}