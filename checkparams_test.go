//go:build checkparams

package PowerSNMPv3

import (
	"errors"
	"fmt"
	"testing"
)

type TestSt struct {
	Val   string
	Valid bool
}

type TestInt struct {
	Val   int
	Valid bool
}

var (
	AuthVariants     = []string{"", "none", "sha", "sha224", "sha256", "sha384", "sha512", "md5", "unmk"}
	PriVariants      = []string{"", "none", "aes", "aes192", "aes256", "aes192a", "aes256a", "des", "unmk"}
	KeyVariant       = []string{"", "1234", "12345"}
	UsersVariant     = []string{"", "user"}
	CommunityVariant = []string{"", "public"}
	IpAddressVarians = []TestSt{TestSt{Val: "192.168.a0.1", Valid: false},
		TestSt{Val: "192.168.0.1", Valid: true},
		TestSt{Val: "2008:4a2f::0:2", Valid: true},
		TestSt{Val: "2008:4r2f::0:2", Valid: false}}
	PortVariant        = []TestInt{TestInt{Val: 655351, Valid: false}, TestInt{Val: -1, Valid: false}, TestInt{Val: 0, Valid: false}, TestInt{Val: 161, Valid: true}}
	SnmpVersionVariant = []TestInt{TestInt{Val: 0, Valid: false}, TestInt{Val: 1, Valid: false}, TestInt{Val: 2, Valid: true}, TestInt{Val: 3, Valid: true}, TestInt{Val: -1, Valid: false}}
)

// Проверим правильнве ли ошибки
func chStructuredErr(t *testing.T, err error, ErrorParam []string, FinalDescr string) {
	var Serr SNMPSetparameters_Errors
	t.Helper()
	founderrn := 0
	if err != nil {
		if errors.As(err, &Serr) {
			if len(Serr.WrongParameters) == 0 {
				t.Fatal("Structured error but no data")
			}
			for _, wp := range Serr.WrongParameters {
				for _, ECp := range ErrorParam {
					if wp.WrongParameter == ECp {
						founderrn++
						continue
					}
				}

			}
			if founderrn != len(ErrorParam) {
				t.Fatalf("Unexpexted errors: %v", Serr)
			}
		} else {
			t.Fatalf("Unstructured error: %v", err)
		}
	} else {
		t.Fatal(FinalDescr)
	}
}

func TestSetAuthPrivParamsStToInt(t *testing.T) {
	for _, AuthProtocol := range AuthVariants {
		for _, PrivProtocol := range PriVariants {
			for _, AuthKey := range KeyVariant {
				for _, PrivKey := range KeyVariant {
					TestDescr := fmt.Sprintf("A=%s|P=%s|AK=%s|PK=%s", AuthProtocol,
						PrivProtocol, AuthKey, PrivKey)

					t.Run(TestDescr, func(t *testing.T) {
						sl, ia, ip, err := CheckSNMPv3StringParams(AuthProtocol, AuthKey, PrivProtocol, PrivKey)

						AuthData, AuthValid := authProtocols[AuthProtocol]
						PrivData, PrivValid := privhProtocols[PrivProtocol]

						var errexsist = false
						var Expectederrstar []string
						var FinalMsgErr = ""

						if !AuthValid && AuthProtocol != "" {
							//Auth протокола нет в списке разрешенных и это не пустая строка
							Expectederrstar = append(Expectederrstar, "auth protocol")
							FinalMsgErr += "Wrong auth protocol but no error,"
							errexsist = true
						}
						if AuthValid || AuthProtocol == "" {
							NoneProto := false
							if AuthProtocol == "" {
								NoneProto = true
							}
							if AuthValid {
								NoneProto = AuthData.non
							}
							if !NoneProto { //Протокол auth не пустой, не none, но ключ Auth короткий
								if len(AuthKey) < SNMP_AUTH_PRIV_KEY_MINLEN {
									Expectederrstar = append(Expectederrstar, "auth key")
									FinalMsgErr += "Auth key too short,"
									errexsist = true
								}
							}
						}

						if !PrivValid && PrivProtocol != "" {
							//Priv протокола нет в списке разрешенных и он не пустая строка
							Expectederrstar = append(Expectederrstar, "priv protocol")
							FinalMsgErr += "Wrong priv protocol but no error,"
							errexsist = true
						}

						//Priv протокол есть в списке или пустая строка
						if PrivValid || PrivProtocol == "" {
							NonePrivProto := false
							if PrivProtocol == "" {
								NonePrivProto = true
							} else {
								NonePrivProto = PrivData.non
							}

							if !NonePrivProto {
								AuthProtoNone := false
								if AuthProtocol == "" {
									AuthProtoNone = true
								}
								if AuthValid && AuthData.non {
									AuthProtoNone = true
								}
								if AuthProtoNone {
									//Протокол priv не пустой, но Auth протокол none
									Expectederrstar = append(Expectederrstar, "priv protocol")
									FinalMsgErr += "Priv protocol wthout auth protocol,"
									errexsist = true
								}
								if !PrivData.non {
									//Протокол priv не пустой, не none, но ключ Priv короткий
									if len(PrivKey) < SNMP_AUTH_PRIV_KEY_MINLEN {
										Expectederrstar = append(Expectederrstar, "priv key")
										FinalMsgErr += "Priv key too short,"
										errexsist = true
									}
								}
							}
						}

						if errexsist {
							t.Log("Structured error is:", err)
							chStructuredErr(t, err, Expectederrstar, FinalMsgErr)
							return
						}
						//Если небыло ошибок то:
						if !errexsist {
							if err != nil {
								t.Errorf("Unexpected error: %v", err)
								return
							}
							if AuthProtocol == "" {
								if ia != AUTH_PROTOCOL_NONE {
									t.Errorf("Expected Auth protocol 0 but got %d", ia)
								}
							} else {
								if AuthValid {
									if AuthData.intVar != ia {
										t.Errorf("Expected Auth protocol %d but got %d", AuthData.intVar, ia)
									}
								}
							}

							if PrivProtocol == "" {
								if ip != PRIV_PROTOCOL_NONE {
									t.Errorf("Expected Priv protocol 0 but got %d", ip)
								}
							} else {
								if PrivValid {
									if PrivData.intVar != ip {
										t.Errorf("Expected Priv protocol %d but got %d", PrivData.intVar, ip)
									}
								}
							}

							if ia > 0 {
								if ip == 0 {
									if sl != SECLEVEL_AUTHNOPRIV {
										t.Errorf("Expected seclevel 1 but got %d", sl)
									}
								} else {
									if sl != SECLEVEL_AUTHPRIV {
										t.Errorf("Expected seclevel 2 but got %d", sl)
									}
								}
							} else {
								if sl != SECLEVEL_NOAUTH_NOPRIV {
									t.Errorf("Expected seclevel 0 but got %d", sl)
								}
							}

						}

						t.Log("retdata:", sl, ia, ip, err)

					})
				}
			}
		}
	}
}

func TestCheckParamsIPandPortSNMP(t *testing.T) {
	for _, CipAddr := range IpAddressVarians {
		for _, CPort := range PortVariant {
			TestDescr := fmt.Sprintf("IP=%s|PORT=%d", CipAddr.Val, CPort.Val)
			t.Run(TestDescr, func(t *testing.T) {

				var cND NetworkDevice
				cND.SNMPparameters.SNMPversion = 0
				cND.IPaddress = "192.168.0.1"
				cND.Port = 161
				cND.SNMPparameters.Username = ""

				err := CheckUserParams(cND)

				if !CipAddr.Valid {
					if err == nil {
						t.Errorf("Expected ip address error but got nil")
						return
					}
				}

				if !CPort.Valid {
					if err == nil {
						t.Errorf("Expected port error but got nil")
						return
					}
				}
			})
		}
	}
}

func TestBasicCheckParamsVersionSNMP(t *testing.T) {
	for _, CVersion := range SnmpVersionVariant {
		TestDescr := fmt.Sprintf("SNMP version=%d", CVersion.Val)
		t.Run(TestDescr, func(t *testing.T) {

			var cND NetworkDevice
			cND.IPaddress = "192.168.0.1"
			cND.Port = 161
			cND.SNMPparameters.SNMPversion = CVersion.Val
			cND.SNMPparameters.Username = ""

			err := CheckUserParams(cND)

			if !CVersion.Valid {
				if err == nil {
					t.Errorf("Expected snmp version error but got nil")
					return
				}
			}
		})
	}
}

func TestBasicCheckParamsVersion2SNMP(t *testing.T) {
	for _, CCommunity := range CommunityVariant {
		TestDescr := fmt.Sprintf("SNMP community=%s", CCommunity)
		t.Run(TestDescr, func(t *testing.T) {

			var cND NetworkDevice
			cND.SNMPparameters.SNMPversion = 2
			cND.IPaddress = "192.168.0.1"
			cND.Port = 161
			cND.SNMPparameters.Username = ""
			cND.SNMPparameters.Community = CCommunity

			err := CheckUserParams(cND)

			if len(CCommunity) == 0 {
				if err == nil {
					t.Errorf("Expected community error but got nil")
					return
				}
			}
		})
	}
}

func TestCheckUserParams(t *testing.T) {
	for _, Cuser := range UsersVariant {
		for _, AuthProtocol := range AuthVariants {
			for _, PrivProtocol := range PriVariants {
				for _, AuthKey := range KeyVariant {
					for _, PrivKey := range KeyVariant {
						TestDescr := fmt.Sprintf("U=%s|A=%s|P=%s|AK=%s|PK=%s", Cuser, AuthProtocol,
							PrivProtocol, AuthKey, PrivKey)

						t.Run(TestDescr, func(t *testing.T) {
							var cND NetworkDevice
							cND.SNMPparameters.SNMPversion = 3
							cND.IPaddress = "192.168.0.1"
							cND.Port = 161
							cND.SNMPparameters.Username = Cuser
							cND.SNMPparameters.AuthProtocol = AuthProtocol
							cND.SNMPparameters.PrivProtocol = PrivProtocol
							cND.SNMPparameters.AuthKey = AuthKey
							cND.SNMPparameters.PrivKey = PrivKey

							err := CheckUserParams(cND)

							if len(Cuser) == 0 {
								if err == nil {
									t.Errorf("Expected username error but got nil")
								}
							}

							AuthData, AuthValid := authProtocols[AuthProtocol]
							PrivData, PrivValid := privhProtocols[PrivProtocol]

							var errexsist = false
							var Expectederrstar []string
							var FinalMsgErr = ""

							if !AuthValid && AuthProtocol != "" {
								//Auth протокола нет в списке разрешенных и это не пустая строка
								Expectederrstar = append(Expectederrstar, "auth protocol")
								FinalMsgErr += "Wrong auth protocol but no error,"
								errexsist = true
							}
							if AuthValid || AuthProtocol == "" {
								NoneProto := false
								if AuthProtocol == "" {
									NoneProto = true
								}
								if AuthValid {
									NoneProto = AuthData.non
								}
								if !NoneProto { //Протокол auth не пустой, не none, но ключ Auth короткий
									if len(AuthKey) < SNMP_AUTH_PRIV_KEY_MINLEN {
										Expectederrstar = append(Expectederrstar, "auth key")
										FinalMsgErr += "Auth key too short,"
										errexsist = true
									}
								}
							}

							if !PrivValid && PrivProtocol != "" {
								//Priv протокола нет в списке разрешенных и он не пустая строка
								Expectederrstar = append(Expectederrstar, "priv protocol")
								FinalMsgErr += "Wrong priv protocol but no error,"
								errexsist = true
							}

							//Priv протокол есть в списке или пустая строка
							if PrivValid || PrivProtocol == "" {
								NonePrivProto := false
								if PrivProtocol == "" {
									NonePrivProto = true
								} else {
									NonePrivProto = PrivData.non
								}

								if !NonePrivProto {
									AuthProtoNone := false
									if AuthProtocol == "" {
										AuthProtoNone = true
									}
									if AuthValid && AuthData.non {
										AuthProtoNone = true
									}
									if AuthProtoNone {
										//Протокол priv не пустой, но Auth протокол none
										Expectederrstar = append(Expectederrstar, "priv protocol")
										FinalMsgErr += "Priv protocol wthout auth protocol,"
										errexsist = true
									}
									if !PrivData.non {
										//Протокол priv не пустой, не none, но ключ Priv короткий
										if len(PrivKey) < SNMP_AUTH_PRIV_KEY_MINLEN {
											Expectederrstar = append(Expectederrstar, "priv key")
											FinalMsgErr += "Priv key too short,"
											errexsist = true
										}
									}
								}
							}

							if errexsist {
								t.Log("Structured error is:", err)
								chStructuredErr(t, err, Expectederrstar, FinalMsgErr)
								return
							}

						})
					}
				}
			}
		}
	}
}
