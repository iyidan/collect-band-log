package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iyidan/zrequest"

	"github.com/iyidan/algorithms/dst/skiplist"
	"github.com/iyidan/logtailer"

	"github.com/iyidan/goutils/cmtjson"
)

const (
	BandDataFromApi  = 0 // 默认
	BandDataFromSync = 1
)

var (
	BandDataFromStrMap = map[string]int{
		"0": BandDataFromApi,
		"1": BandDataFromSync,
	}
)

type BandItem struct {
	Ip           string    `json:"Ip"`
	PopId        int64     `json:"PopId"`
	Server       int       `json:"Server"`
	BandwidthIn  float64   `json:"InBandwidth"`
	BandwidthOut float64   `json:"OutBandwidth"`
	DataFrom     int       `json:"DataFrom"` // 带宽数据来源
	Time         time.Time `json:"time"`
}

type Store struct {
	lock sync.RWMutex
	data map[string]*skiplist.Skiplist // ip -> ip-band time sorted
}

func (s *Store) Add(item *BandItem) {
	s.lock.Lock()
	defer s.lock.Unlock()
	sl, ok := s.data[item.Ip]
	if !ok {
		sl = skiplist.New(compareFunc)
		s.data[item.Ip] = sl
	}
	sl.Add(item, float64(item.Time.Unix()))
}

func (s *Store) PrintIPData(pType string, pf string, filename string) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var ips []string
	pData := map[string]string{}

	for ip, sl := range s.data {
		ips = append(ips, ip)
		pData[ip] = genBandDataString(pf, "%-15s", ip, sl, 0, math.MaxFloat64, pType)
	}

	writter := os.Stderr
	if filename != "" {
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			panic(fmt.Errorf("open output file failed: %v", err))
		}
		defer file.Close()
		writter = file
	}
	fmt.Fprintf(writter, "-------- ip band data(%s) --------\n", pType)
	sort.Strings(ips)
	for _, ip := range ips {
		fmt.Fprintln(writter, pData[ip])
	}

}

type APIBaseRes struct {
	Code    int
	Message string
}

type APIIdcRes struct {
	APIBaseRes
	Data struct {
		Items []struct {
			Id      int
			Name    string
			Chname  string
			Monitor struct {
				Snmp_ip string
			}
		}
	}
}

func (s *Store) PrintIdcData(pType string, pf string, filename string) {
	api := conf.DispatchHost + "/api/v2/admin/idcs"
	idcs := &APIIdcRes{}
	err := zrequest.Open().Get(api).Unmarshal(idcs)
	if err != nil {
		panic(fmt.Errorf("PrintIdcData: get idcs failed: %v", err.Error()))
	}
	if idcs.Code != 200 {
		panic(fmt.Errorf("PrintIdcData: get idcs failed: code:%v,message:%v", idcs.Code, idcs.Message))
	}
	if len(idcs.Data.Items) == 0 {
		panic(fmt.Errorf("PrintIdcData: get idcs failed: no idcs"))
	}
	var idcNames []string
	idcsBandData := make(map[string]string)

	s.lock.RLock()
	defer s.lock.RUnlock()

	for _, idc := range idcs.Data.Items {
		//name := idc.Chname + "(" + idc.Name + ")"
		name := fmt.Sprintf("%s(%s)", idc.Name, idc.Monitor.Snmp_ip)
		idcNames = append(idcNames, name)
		if idc.Monitor.Snmp_ip == "" {
			if pf == PFCsv {
				idcsBandData[name] = fmt.Sprintf("%s,nosnmpip", name)
			} else {
				idcsBandData[name] = fmt.Sprintf("%-25s nosnmpip", name)
			}
			continue
		}
		sl, ok := s.data[idc.Monitor.Snmp_ip]
		if !ok {
			if pf == PFCsv {
				idcsBandData[name] = fmt.Sprintf("%s,nobanddata", name)
			} else {
				idcsBandData[name] = fmt.Sprintf("%-25s nobanddata", name)
			}
			continue
		}
		idcsBandData[name] = genBandDataString(pf, "%-25s", name, sl, 0, math.MaxFloat64, pType)
	}

	writter := os.Stderr
	if filename != "" {
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			panic(fmt.Errorf("open output file failed: %v", err))
		}
		defer file.Close()
		writter = file
	}
	sort.Strings(idcNames)
	fmt.Fprintf(writter, "-------- idc band data(%s) --------\n", pType)
	for _, name := range idcNames {
		fmt.Fprintln(writter, idcsBandData[name])
	}
}

type APIGroupIpsRes struct {
	APIBaseRes
	Data []struct {
		Idc_name string
		Name     string
		Rips     []string
		Vips     []string
	}
}

func (s *Store) PrintGroupData(pType string, pf string, filename string) {
	api := conf.DispatchHost + "/api/v2/admin/groups/ips"
	groups := &APIGroupIpsRes{}
	err := zrequest.Open().Get(api).Unmarshal(groups)
	if err != nil {
		panic(fmt.Errorf("PrintGroupData: get groups failed: %v", err.Error()))
	}
	if groups.Code != 200 {
		panic(fmt.Errorf("PrintGroupData: get groups failed: code:%v,message:%v", groups.Code, groups.Message))
	}
	if len(groups.Data) == 0 {
		panic(fmt.Errorf("PrintGroupData: get groups failed: no groups"))
	}
	var groupNames []string
	groupsBandData := make(map[string]string)

	s.lock.RLock()
	defer s.lock.RUnlock()

	for _, group := range groups.Data {
		name := fmt.Sprintf("%s(%s)", group.Name, group.Idc_name)
		groupNames = append(groupNames, name)
		if len(group.Rips) == 0 {
			if pf == PFCsv {
				groupsBandData[name] = fmt.Sprintf("%s,norip", name)
			} else {
				groupsBandData[name] = fmt.Sprintf("%-20s norip", name)
			}
			continue
		}
		var sumTimePoints []time.Time
		sumValues := make(map[time.Time]*skiplist.Node)
		for _, rip := range group.Rips {
			sl, ok := s.data[rip]
			if !ok {
				continue
			}
			values := sl.RangeByScore(0, math.MaxFloat64)
			for _, value := range values {
				item := value.Data.(*BandItem)
				if n, ok := sumValues[item.Time]; !ok {
					tmp := *item
					sumValues[item.Time] = &skiplist.Node{
						Score: value.Score,
						Data:  &tmp,
					}
					sumTimePoints = append(sumTimePoints, item.Time)
				} else {
					b := n.Data.(*BandItem)
					b.BandwidthIn += item.BandwidthIn
					b.BandwidthOut += item.BandwidthOut
				}
			}
		}
		var values []*skiplist.Node
		for _, t := range sumTimePoints {
			values = append(values, sumValues[t])
		}
		groupsBandData[name] = genBandDataStringByValues(pf, "%-20s", name, pType, values)
	}

	writter := os.Stderr
	if filename != "" {
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			panic(fmt.Errorf("open output file failed: %v", err))
		}
		defer file.Close()
		writter = file
	}
	sort.Strings(groupNames)
	fmt.Fprintf(writter, "-------- group band data(%s) --------\n", pType)
	for _, name := range groupNames {
		fmt.Fprintln(writter, groupsBandData[name])
	}
}

func genBandDataString(pf, ipFormat, ip string, sl *skiplist.Skiplist, min, max float64, pType string) string {
	values := sl.RangeByScore(min, max)
	return genBandDataStringByValues(pf, ipFormat, ip, pType, values)
}

func genBandDataStringByValues(pf, ipFormat, ip, pType string, values []*skiplist.Node) string {
	var s []string
	if pf == PFCsv {
		s = append(s, ip)
	} else {
		s = append(s, fmt.Sprintf(ipFormat, ip))
	}

	if len(values) > 0 {
		startT := values[0].Data.(*BandItem).Time.Format("01/02T15:04:05")
		endT := values[len(values)-1].Data.(*BandItem).Time.Format("01/02T15:04:05")
		s = append(s, fmt.Sprintf("%s-%s", startT, endT))
	}
	for _, value := range values {
		item := value.Data.(*BandItem)
		if pType == TypeIn {
			s = append(s, fmt.Sprintf("%.2f", item.BandwidthIn))
		} else if pType == TypeOut {
			s = append(s, fmt.Sprintf("%.2f", item.BandwidthOut))
		} else {
			s = append(s, fmt.Sprintf("%.2f|%.2f", item.BandwidthIn, item.BandwidthOut))
		}
	}

	if pf == PFCsv {
		return strings.Join(s, ",")
	}
	return strings.Join(s, " ")
}

// Config rule configs
type Config struct {
	Debug        bool                 `json:"debug"`
	DispatchHost string               `json:"dispatch_host"`
	Rule         *logtailer.WatchRule `json:"rule"`
	Type         string               `json:"type"`
	Action       string               `json:"action"`
	Format       string               `json:"format"`
	OutputFile   string               `json:"output_file"`
}

const (
	TypeIn      = "in"
	TypeOut     = "out"
	TypeAll     = "all"
	ActionIP    = "ip"
	ActionIdc   = "idc"
	AcitonGroup = "group"
	ActionAll   = "all"
	PFCsv       = "csv"
	PFSpace     = "space"
)

var (
	confFile    string
	conf        = &Config{}
	store       = &Store{data: make(map[string]*skiplist.Skiplist)}
	compareFunc = func(a, b interface{}) int { return 0 }
	typeMap     = map[string]struct{}{
		TypeIn:  struct{}{},
		TypeOut: struct{}{},
		TypeAll: struct{}{},
	}
	actionsMap = map[string]func(){
		ActionIP:    func() { store.PrintIPData(conf.Type, conf.Format, conf.OutputFile) },
		ActionIdc:   func() { store.PrintIdcData(conf.Type, conf.Format, conf.OutputFile) },
		AcitonGroup: func() { store.PrintGroupData(conf.Type, conf.Format, conf.OutputFile) },
		ActionAll: func() {
			store.PrintIPData(conf.Type, conf.Format, conf.OutputFile)
			store.PrintIdcData(conf.Type, conf.Format, conf.OutputFile)
			store.PrintGroupData(conf.Type, conf.Format, conf.OutputFile)
		},
	}
	pfMap = map[string]struct{}{
		PFCsv:   struct{}{},
		PFSpace: struct{}{},
	}
)

func init() {
	flag.StringVar(&confFile, "f", "", "the configure file")
}

func main() {
	flag.Parse()
	if confFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := cmtjson.ParseFromFile(confFile, conf); err != nil {
		panic(err)
	}

	if _, ok := actionsMap[conf.Action]; !ok {
		log.Panicf("action not supported: %s", conf.Action)
	}
	if _, ok := typeMap[conf.Type]; !ok {
		log.Panicf("type not supported: %s", conf.Type)
	}
	if _, ok := pfMap[conf.Format]; !ok {
		log.Panicf("format not supported: %s", conf.Type)
	}

	if conf.Debug {
		logtailer.Debug = true
	}

	conf.Rule.Handler = handleBandReportOne

	// process rules
	if err := conf.Rule.Process(); err != nil {
		log.Panicf("rule process error: %v, %v", conf.Rule.Path, err)
	}
	log.Printf("waitting for completed")
	conf.Rule.Wait()
	log.Printf("stoped")

	actionsMap[conf.Action]()
}

// not concurrence safe
func handleBandReportOne(rule *logtailer.WatchRule, matchedIdx uint64, logTime time.Time, line string) {
	a := strings.Split(line, "[{")
	if len(a) != 2 {
		return
	}
	aa := strings.Split(strings.Trim(a[1], "}]"), "} {")
	if len(aa) == 0 {
		return
	}
	// "36.42.77.1 677 0 1762.19 6077.3 0"
	for _, v := range aa {
		av := strings.Split(v, " ")
		if len(av) != 6 {
			continue
		}
		item := &BandItem{}
		item.Ip = av[0]
		item.PopId, _ = strconv.ParseInt(av[1], 10, 64)
		if av[2] == "1" {
			item.Server = 1
		}
		item.BandwidthIn, _ = strconv.ParseFloat(av[3], 64)
		item.BandwidthOut, _ = strconv.ParseFloat(av[4], 64)
		item.DataFrom = BandDataFromStrMap[av[5]]
		item.Time = logTime
		store.Add(item)
	}
}
