package main

import (
	"sort"
	"strings"
	"fmt"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"qiniupkg.com/x/url.v7"
	"time"
	"reflect"
	"github.com/parnurzeal/gorequest"
	"errors"
	"encoding/json"
	"math/rand"
)

type PublicVar struct {
	//Action          string
	Region          string
	Timestamp       string
	Nonce           string
	SignatureMethod string
	SecretId        string
}
type LbInfoVar struct {
	forward string `json:"forward"`
	limit string `json:"limit"`
}
type LbInfo struct {
	Code            int                   `json:"code"`
	Message         string                `json:"message"`
	CodeDesc        string                `json:"codeDesc"`
	TotalCount      int                   `json:"totalCount"`
	LoadBalancerSet []LoadBalancerSetInfo `json:"loadBalancerSet"`
}

type LoadBalancerSetInfo struct {
	LoadBalancerId   string      `json:"loadBalancerId"`
	UnLoadBalancerId string      `json:"unLoadBalancerId"`
	LoadBalancerName string      `json:"loadBalancerName"`
	LoadBalancerType int         `json:"loadBalancerType"`
	Domain           string      `json:"domain"`
	LoadBalancerVips interface{} `json:"loadBalancerVips"`
	Status           int         `json:"status"`
	CreateTime       string      `json:"createTime"`
	StatusTime       string      `json:"statusTime"`
	VpcId            int         `json:"vpcId"`
	UniqVpcId        string      `json:"uniqVpcId"`
	subnetId         string      `json:"subnetId"`
	ProjectId        int         `json:"projectId"`
	Forward          int         `json:"forward"`
	Snat             bool        `json:"snat"`
	OpenBgp          int         `json:"openBgp"`
	Isolation        int         `json:"isolation"`
	Log              string      `json:"log"`
	RsRegionInfo struct {
		region string `json:"region"`
		VpcId  string `json:"vpcId"`
	} `json:"rsRegionInfo"`
	LbChargeType string `json:"lbChargeType"`
	LbChargePrepaid struct {
		Period    int    `json:"period"`
		RenewFlag string `json:"renewFlag"`
	} `json:"lbChargePrepaid"`
	InternetAccessible struct {
		InternetChargeType      string `json:"internetChargeType"`
		InternetMaxBandwidthOut int    `json:"internetMaxBandwidthOut"`
	} `json:"internetAccessible"`
	IsolatedTime string      `json:"isolatedTime"`
	ExpireTime   string      `json:"expireTime"`
	SecureGroups interface{} `json:"SecureGroups"`
	ConfigId     string      `json:"ConfigId"`
	TagInfo      interface{} `json:"tagInfo"`
	anycastZone  string      `json:"anycastZone"`
}
type LbPortVar struct {
	loadBalancerId string `json:"loadBalancerId"`
	protocol string `json:"protocol"`
}

type LbPort struct {
	Code        int               `json:"code"`
	Message     string            `json:"message"`
	CodeDesc    string            `json:"codeDesc"`
	ListenerSet []ListenerSetInfo `json:"listenerSet"`
}

type ListenerSetInfo struct {
	LoadBalancerPort int      `json:"loadBalancerPort"`
	Protocol         int      `json:"protocol"`
	ListenerName     string   `json:"listenerName"`
	ProtocolType     string   `json:"protocolType"`
	ListenerId       string   `json:"listenerId"`
	AddTimestamp     string   `json:"addTimestamp"`
	Rules            []RulesInfo `json:"rules"`
}
type RulesInfo struct {
	LocationId string `json:"locationId"`
	Domain string  `json:"domain"`
	Url string `json:"url"`
	HttpHash string `json:"httpHash"`
	TargetuListenerId string `json:"targetuListenerId"`
	TargetuLocationId string `json:"targetuLocationId"`
	BAutoCreated int `json:"bAutoCreated"`
	SessionExpire int `json:"sessionExpire"`
	HealthSwitch int `json:"healthSwitch"`
	TimeOut int  `json:"timeOut"`
	IntervalTime int `json:"intervalTime"`
	HealthNum int `json:"healthNum"`
	UnhealthNum int `json:"unhealthNum"`
	HttpCode int `json:"httpCode"`
	HttpCheckPath string `json:"httpCheckPath"`
	HttpCheckDomain string `json:"httpCheckDomain"`
	HttpCheckMethod string `json:"httpCheckMethod"`
	DefaultServer int `json:"defaultServer"`
	Http2 string `json:"http2"`
}
type LbDomainVar struct {
	loadBalancerId string `json:"loadBalancerId"`
	listenerId     string `json:"listenerId"`
	domain         string `json:"domain"`
	attribute      string `json:"attribute"`
	on             string `json:"on"`
}

type LbDomain struct {
	Code     int    `json:"code"`
	Message  string `json:"message"`
	CodeDesc string `json:"codeDesc"`
}

const (
	SecretId  string = "*"
	API       string = "lb.api.qcloud.com/v2/index.php?"
	SecretKey string = "*"
)

func GetSortVar(publicVar PublicVar, obj interface{}, action string) string {

	varMap := make(map[string]string)
	varMap["Action"] = action
	varMap["Region"] = publicVar.Region
	varMap["Timestamp"] = string(publicVar.Timestamp)
	varMap["Nonce"] = fmt.Sprintf("%d", func() int {
		rand.Seed(time.Now().Unix())
		randNum := rand.Intn(10000000)
		return randNum
	}())
	varMap["SignatureMethod"] = publicVar.SignatureMethod
	varMap["SecretId"] = SecretId

	typeObj := reflect.TypeOf(obj)
	valueObj := reflect.ValueOf(obj)

	for i := 0; i < typeObj.NumField(); i++ {
		field := typeObj.Field(i)
		value := valueObj.Field(i).String()
		//fmt.Printf("%s: %v = %v\n", field.Name, field.Type, value)
		varMap[field.Name] = value
	}
	//fmt.Println(varMap)

	var varSlice []string
	for key, _ := range varMap {
		varSlice = append(varSlice, key)
	}
	sort.Strings(varSlice)
	//sort
	var str string
	for i := 0; i < len(varSlice); i++ {
		str += fmt.Sprintf("%s", varSlice[i]+"="+varMap[varSlice[i]]+"&")
	}
	return str
}
func GetRequestUrl(publicVar PublicVar, obj interface{}, api string, action string) string {
	str := GetSortVar(publicVar, obj, action)
	//get Signature
	pinStr := "GET" + api + strings.Trim(str, "&")
	signByte := []byte{}
	temp := hmac.New(sha256.New, []byte(SecretKey))
	temp.Write([]byte(pinStr))
	signByte = temp.Sum(nil)
	signStr := base64.StdEncoding.EncodeToString(signByte)
	signStr = url.QueryEscape(signStr)

	//get request
	requestUrl := "https://" + api + str + "Signature=" + signStr
	return requestUrl

}

func SentQequest(requestUrl string) string {
	request := gorequest.New()
	resp, body, errs := request.Get(requestUrl).End()
	if resp.StatusCode != 200 || len(errs) != 0 {
		newError := errors.New("resp is not 200 or errs is not null")
		fmt.Println(newError.Error())
	}
	return body
}
func main() {
	var publicVar PublicVar
	//lbinfo
	var lbInfoVar LbInfoVar
	var lbInfo LbInfo
	//lbportinfo
	var lbPortVar LbPortVar
	var lbPort LbPort
	////lbdomain
	var lbDomainVar LbDomainVar
	//var lbDomain LbDomain

	//publicvar
	publicVar.SecretId = SecretId
	publicVar.SignatureMethod = "HmacSHA256"
	//publicVar.Nonce = fmt.Sprintf("%d", func() int {
	//	rand.Seed(time.Now().Unix())
	//	randNum := rand.Intn(10000000)
	//	return randNum
	//}())
	publicVar.Timestamp = fmt.Sprintf("%d", time.Now().Unix())
	publicVar.Region = "sh"

	//lbinfovar
	lbInfoVar.forward = "1"
	lbInfoVar.limit = "100"

	//DescribeLoadBalancers request
	api := "lb.api.qcloud.com/v2/index.php?"
	action := "DescribeLoadBalancers"
	requestUrl := GetRequestUrl(publicVar, lbInfoVar, api, action)
	//go request
	body := SentQequest(requestUrl)
	json.Unmarshal([]byte(body), &lbInfo)
	var lbId []string
	for _,v := range lbInfo.LoadBalancerSet {
		lbId = append(lbId,v.LoadBalancerId)
	}
	//fmt.Println(lbId)
	for _,v1 := range lbId {
		action = "DescribeForwardLBListeners"
		lbPortVar.loadBalancerId = v1
		lbPortVar.protocol = "4"
		requestUrl := GetRequestUrl(publicVar, lbPortVar, api, action)
		//fmt.Println(requestUrl)
		body := SentQequest(requestUrl)
		json.Unmarshal([]byte(body),&lbPort)
		for _,v2 := range lbPort.ListenerSet {
				for _,v3 := range v2.Rules {
					lbDomainVar.loadBalancerId = v1
					lbDomainVar.listenerId = v2.ListenerId
					lbDomainVar.domain = v3.Domain
					lbDomainVar.attribute = "http2"
					lbDomainVar.on="1"
					action = "SetSeventhListenerDomainAttributes"
					requestUrl := GetRequestUrl(publicVar, lbDomainVar, api, action)
					fmt.Println(requestUrl)
					fmt.Println(SentQequest(requestUrl))
				}
			}
		}
	}
