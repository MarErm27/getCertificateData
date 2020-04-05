package getCertificateData

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"golang.org/x/text/encoding/charmap"
	//"strconv"
	//"encoding/json"
	//"github.com/tobischo/gokeepasslib"
)

func toUtf8(iso8859_1_buf []byte) string {
	buf := make([]rune, len(iso8859_1_buf))
	for i, b := range iso8859_1_buf {
		buf[i] = rune(b)
	}
	return string(buf)
}

func cutEntryValue(startOfEntry string, endOfEntry string) string {
	indexOfendOfEntry := strings.Index(startOfEntry, endOfEntry)
	strBytes := []byte(startOfEntry)
	if indexOfendOfEntry != -1 {
		entryValue := string(strBytes[0:indexOfendOfEntry])
		return entryValue
	} else {
		// trimEntry1 := strings.TrimRight(startOfEntry," ")
		// trimEntry2 := strings.TrimRight(trimEntry1, "\r\n")
		// trimEntry3 := strings.TrimRight(trimEntry2," ")
		indexLineBreak := strings.Index(startOfEntry, "\r\n")
		rawEntryValue := string(strBytes[0:indexLineBreak])
		entryValue := strings.TrimRight(rawEntryValue, " ")
		return entryValue
	}
}

func getEntry(str string, stringToSearch string) string {
	strContainsEntry := strings.Contains(str, stringToSearch)
	if strContainsEntry {
		startOfEntrySlice := strings.Split(str, stringToSearch)
		startOfEntry := startOfEntrySlice[1]
		if strings.Contains(stringToSearch, "STREET") {
			endOfEntry := "\","
			return cutEntryValue(startOfEntry, endOfEntry)
		} else if strings.Contains(stringToSearch, "\\rutoken") {
			endOfEntry := "\\"
			return cutEntryValue(startOfEntry, endOfEntry)
		} else {
			endOfEntry := ","
			return cutEntryValue(startOfEntry, endOfEntry)
		}
	}
	return ""
}

func getSlicesOfEntries(cert *string, entryName string, stringToSearch string, c *[]map[string]Vertex) {
	subjectName := strings.Split(*cert, "Subject Name:")
	//fmt.Println(subjectName[1])
	splitSubjectPublicKeyAlgorithmIdentifier := strings.Split(subjectName[1], "Subject Public Key Algorithm Identifier")
	//fmt.Println(splitSubjectPublicKeyAlgorithmIdentifier[0])

	if entryName == "Fingerprint" {
		rawFingerprint := strings.Split(splitSubjectPublicKeyAlgorithmIdentifier[1], "Fingerprint:")
		entryValue := getEntry(rawFingerprint[1], stringToSearch)
		m = make(map[string]Vertex)
		m[entryName] = Vertex{
			entryValue,
		}
		*c = append(*c, m)
	} else if entryName == "TokenID" {
		entryValue := getEntry(subjectName[0], stringToSearch)
		m = make(map[string]Vertex)
		m[entryName] = Vertex{
			entryValue,
		}
		*c = append(*c, m)
	} else if entryName == "NotBefore" || entryName == "NotAfter" {
		entryValue := getEntry(splitSubjectPublicKeyAlgorithmIdentifier[1], stringToSearch)
		m = make(map[string]Vertex)
		m[entryName] = Vertex{
			entryValue,
		}
		*c = append(*c, m)
	} else {
		onlySubjectNameString := splitSubjectPublicKeyAlgorithmIdentifier[0]
		entryValue := getEntry(onlySubjectNameString, stringToSearch)
		m = make(map[string]Vertex)
		m[entryName] = Vertex{
			entryValue,
		}
		*c = append(*c, m)
	}
}

func setEntriesNames() map[string]Entry {
	e = make(map[string]Entry)
	e["TokenID"] = Entry{
		"\\rutoken",
	}
	e["ИНН"] = Entry{
		" ИНН=",
	}
	e["СНИЛС"] = Entry{
		" СНИЛС=",
	}
	e["ОГРН"] = Entry{
		" ОГРН=",
	}
	e["ОГРНИП"] = Entry{
		" ОГРНИП=",
	}
	e["Title"] = Entry{
		" CN=",
	}
	e["STREET"] = Entry{
		" STREET=\"",
	}
	e["EMAIL"] = Entry{
		" E=",
	}
	// e["C"] = Entry{
	//   " C=",
	// }
	// e["S"] = Entry{
	//   " S=",
	// }
	// e["L"] = Entry{
	//   " L=",
	// }
	e["O"] = Entry{
		" O=",
	}
	e["T"] = Entry{
		" T=",
	}
	e["ИмяОтчество"] = Entry{
		" G=",
	}
	e["Фамилия"] = Entry{
		" SN=",
	}
	e["UnstructuredName"] = Entry{
		" OID.1.2.840.113549.1.9.2=",
	}
	e["NotBefore"] = Entry{
		"Not Before: ",
	}
	e["NotAfter"] = Entry{
		"Not After: ",
	}
	e["Fingerprint"] = Entry{
		"Value: ",
	}
	// e["OU"] = Entry{
	//   " OU=",
	// }
	return e
}

type Str struct {
	Value []map[string]Vertex
}
type Vertex struct {
	Value string
}
type Entry struct {
	Value string
}

var m map[string]Vertex
var e map[string]Entry

func GetSlice() *[][]map[string]Vertex {
	fmt.Printf("Reading certs...\n")
	in, err := exec.Command("Read-GOST34.10-2012-512.exe").Output()
	if err != nil {
		log.Fatal(err)
	}

	d := charmap.Windows1251.NewDecoder()
	out, err := d.Bytes(in)
	if err != nil {
		panic(err)
	}

	certInfo := string(out)
	//fmt.Println(certInfo)
	certs := strings.Split(certInfo, "Container name No ")

	e := setEntriesNames()
	s := [][]map[string]Vertex{}

	for i, cert := range certs {
		if i > 0 {
			//fmt.Println(cert)
			c := []map[string]Vertex{}
			for name, stringToSearch := range e {
				getSlicesOfEntries(&cert, name, stringToSearch.Value, &c)
			}
			s = append(s, c)
		}
	}

	// for certNumber, c := range s{
	//   for entryNumber, value := range c{
	//     for entryName, entryValue := range value{
	//       fmt.Println(certNumber, entryNumber, entryName, entryValue.Value)
	//     }
	//   }
	//   fmt.Println("----------------------")
	// }
	// fmt.Println("FINISH")
	return (&s)
}
