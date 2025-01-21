package dmetric

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var Manager = NewDmetricManager()

type DmetricManager struct {
	hitCounters map[string]prometheus.Counter
	argGauges   map[string]prometheus.Gauge
}

func NewDmetricManager() *DmetricManager {

	return &DmetricManager{
		hitCounters: make(map[string]prometheus.Counter),
		argGauges:   make(map[string]prometheus.Gauge),
	}
}

func (d *DmetricManager) CountHit(name string) {
	name = replaceDotWithUnderscore(name)
	if _, ok := d.hitCounters[name]; !ok {

		d.hitCounters[name] = promauto.NewCounter(prometheus.CounterOpts{
			Name: name,
			Help: "The total number of function hits",
		})
	}
	d.hitCounters[name].Inc()
}

func genMetricNamebyFuncName(name string) string {
	name = replaceDotWithUnderscore(name)

	return name + "_hit"
}

func replaceDotWithUnderscore(input string) string { return strings.ReplaceAll(input, ".", "_") }

func (d *DmetricManager) SetArgumentGauge(fName string, argName string, value int) {

	name := fName + "_" + argName
	name = replaceDotWithUnderscore(name)
	if _, ok := d.argGauges[name]; !ok {
		d.argGauges[name] = promauto.NewGauge(prometheus.GaugeOpts{
			Name: name,
			Help: "The argument value of the function",
		})
	}
	d.argGauges[name].Set(float64(value))
}
