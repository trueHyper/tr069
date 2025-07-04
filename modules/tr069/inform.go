package tr069

import (
	"bytes"
	"text/template"
	"time"
	"strings"
	"encoding/xml"
)

/*
	Template for Inform request
*/
const inform_request = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" 
                  xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                  xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soapenv:Header>
    <cwmp:ID soapenv:mustUnderstand="0">{{.ID}}</cwmp:ID>
  </soapenv:Header>
  <soapenv:Body>
    <cwmp:Inform>
      <DeviceId>
        <Manufacturer>{{.Manufacturer}}</Manufacturer>
        <OUI>{{.OUI}}</OUI>
        <ProductClass>{{.ProductClass}}</ProductClass>
        <SerialNumber>{{.SerialNumber}}</SerialNumber>
      </DeviceId>
      <Event soapenc:arrayType="cwmp:EventStruct[1]">
        <EventStruct>
          <EventCode>0 BOOTSTRAP</EventCode>
          <CommandKey></CommandKey>
        </EventStruct>
      </Event>
      <MaxEnvelopes>1</MaxEnvelopes>
      <CurrentTime>{{.CurrentTime}}</CurrentTime>
      <RetryCount>0</RetryCount>
      <ParameterList soapenc:arrayType="cwmp:ParameterValueStruct[{{len .Parameters}}]">
{{range .Parameters}}        <ParameterValueStruct>
          <Name>{{.Name}}</Name>
          <Value xsi:type="xsd:{{.Type}}">{{.Value}}</Value>
        </ParameterValueStruct>
{{end}}      </ParameterList>
    </cwmp:Inform>
  </soapenv:Body>
</soapenv:Envelope>`

type InformData struct {
	ID           string
	Manufacturer string
	OUI          string
	ProductClass string
	SerialNumber string
	CurrentTime  string
	Parameters   []struct {
		Name  string
		Type  string
		Value string
	}
}

func generateInformXML() (string, error) {
	data := InformData{
		ID:           "123",
		Manufacturer: "ACME Networks",
		OUI:          "DECADE",
		ProductClass: "G3000E",
		SerialNumber: "G3000E-9799109101",
		CurrentTime:  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Parameters: []struct {
			Name  string
			Type  string
			Value string
		}{
			{"Device.DeviceInfo.HardwareVersion", "string", "1.0"},
			{"Device.DeviceInfo.ProvisioningCode", "string", "provisioning.code"},
			{"Device.DeviceInfo.SoftwareVersion", "string", "G3000E-1.2.3"},
		},
	}
	tmpl, err := template.New("inform").Parse(inform_request)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

/*
	Checks if xmlBody is a valid CWMP Envelope
*/
func isValidCWMPEnvelope(xmlBody string) bool {
	dec := xml.NewDecoder(strings.NewReader(xmlBody))

	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch se := tok.(type) {
		case xml.StartElement:
			local := strings.ToLower(se.Name.Local)
			ns := strings.ToLower(se.Name.Space)

			if local == "envelope" && strings.Contains(ns, "soap/envelope") {
				return containsCWMP(dec)
			}
		}
	}
}

func containsCWMP(dec *xml.Decoder) bool {
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch se := tok.(type) {
		case xml.StartElement:
			if strings.HasPrefix(strings.ToLower(se.Name.Space), "urn:dslforum-org:cwmp") {
				return true
			}
		}
	}
}