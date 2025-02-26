/*
Copyright © 2025 Red Hat, Inc.
*/

package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// LDAPClient Structure for holding singleton LDAP connection
type LDAPClient struct {
	conn *ldap.Conn
}

// Transform is a Functor Type
type Transform func(string) string

var target string
var kubeconfig string
var outputFile string

var (
	instance *LDAPClient
	once     sync.Once
)

// migrateCmd represents the migrate command
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate sub-command",
	Long: `Migrate subcommand making calls to k8s to migrate tenanat RoleBndings
	from KubeSaw accounts to sso users`,
	Run: func(cmd *cobra.Command, args []string) {

		//Load KubeConfig
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Failed to load kubeconfig: %v", err)
		}

		//Init dynamic client
		dynclient, err := dynamic.NewForConfig(config)
		if err != nil {
			log.Fatalf("Failed to create k8s client: %v", err)
		}

		//Get User Accounts
		userAcctGVR := schema.GroupVersionResource{
			Group:    "toolchain.dev.openshift.com",
			Version:  "v1alpha1",
			Resource: "useraccounts",
		}

		userAccounts, err := dynclient.Resource(userAcctGVR).Namespace("toolchain-member-operator").List(cmd.Context(), metav1.ListOptions{})
		if err != nil {
			log.Fatalf("Failed to list user accounts: %v", err)
		}

		fmt.Printf("Found %d user accounts in toolchain-member-operator namespace:\n", len(userAccounts.Items))

		var idMap map[string]string
		switch target {
		case "email":
			fmt.Println("migrate called for email")
			idMap = buildIDMap(userAccounts, cleanEmail)
		case "user":
			lc := getLDAPClient()
			fmt.Println("migrate called for user name")
			idMap = buildIDMap(userAccounts, getUser)
			lc.conn.Close()
		default:
			fmt.Println("Please select the target identity attribute by passing -t Flag")
			cmd.Help()
			return
		}

		migrate(idMap, cmd.Context())
	},
}

func getLDAPClient() *LDAPClient {
	once.Do(func() {
		ldapServer := "ldap.corp.redhat.com"
		ldapPort := 389
		ldapHost := fmt.Sprintf("%s:%d", ldapServer, ldapPort)
		conn, err := ldap.Dial("tcp", ldapHost)

		if err != nil {
			log.Fatalf("Failed to connect to LDAP server: %v", err)
		}

		instance = &LDAPClient{conn: conn}
	})
	return instance
}

func cleanEmail(email string) string {
	re := regexp.MustCompile(`\+[^@]+@`)

	cEmail := re.ReplaceAllString(email, "@")

	return cEmail
}

func searchLDAP(email string, emailField string) string {
	lc := getLDAPClient()

	searchBase := "ou=users,dc=redhat,dc=com"
	searchFilter := fmt.Sprintf("(%s=%s)", emailField, email)

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		searchFilter,
		[]string{"uid"},
		nil,
	)

	sr, err := lc.conn.Search(searchRequest)

	if err != nil {
		log.Fatalf("Error found searching for email %s: %v\n", email, err)
	}

	if len(sr.Entries) == 0 {
		
		return ""
	}

	return sr.Entries[0].GetAttributeValue("uid")
}

func getUser(email string) string {
	cEmail := cleanEmail(email)

	// searching by mail
	userName := searchLDAP(cEmail, "mail")

	if userName == "" {
		// trying search by alias
		userName = searchLDAP(cEmail, "rhatPreferredAlias")

		if userName == "" {
			fmt.Printf("No user found for email %s\n", cEmail)
		}
	}

	return userName
	
}

func buildIDMap(userAccounts *unstructured.UnstructuredList, transform Transform) map[string]string {
	idMap := make(map[string]string)
	for _, account := range userAccounts.Items {
		name := account.GetName()
		spec, ok := account.Object["spec"].(map[string]interface{})
		if !ok {
			fmt.Printf("UserAccount %s: spec not found")
			continue
		}

		claims, ok := spec["propagatedClaims"].(map[string]interface{})
		if !ok {
			fmt.Printf("UserAccount %s: claims not found")
			continue
		}

		email, ok := claims["email"].(string)
		if !ok {
			fmt.Printf("UserAccount %s: email not found")
			continue
		}

		id := transform(email)

		if id != "" { //no need to map if empty since id was not found
			idMap[name] = id
		}

	}

	return idMap
}

func getTenantNamespaces(clientset *kubernetes.Clientset, ctx context.Context) []string {
	//Get Namespaces
	labelSelector := "toolchain.dev.openshift.com/type=tenant"

	ns, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		log.Fatalf("Failed to list namespace: %v", err)
	}

	nsNum := len(ns.Items)

	namespaces := make([]string, 0, nsNum)

	for _, namespace := range ns.Items {
		nsName := namespace.Name
		namespaces = append(namespaces, nsName)
	}

	return namespaces
}

func getTenantRoleBindings(clientset *kubernetes.Clientset, ctx context.Context) []rbacv1.RoleBinding {
	//Get RoleBindings
	labelSelector := "toolchain.dev.openshift.com/provider=codeready-toolchain"

	fmt.Printf("Gathering information for Tenant Namespaces\n")

	rbs, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		log.Fatalf("Failed to list Tenant RoleBindings: %v", err)
	}

	rbList := make([]rbacv1.RoleBinding, 0, len(rbs.Items))

	for _, rb := range rbs.Items {
		rbName := rb.Name
		rbNamespace := rb.Namespace
		if rbName == "appstudio-pipelines-runner-rolebinding" {
			continue
		}

		if rbNamespace == "toolchain-host-operator" {
			continue
		}

		rbList = append(rbList, rb)
	}

	return rbList
}

func mutateTenantRoleBindings(idMap map[string]string, rbList []rbacv1.RoleBinding) []rbacv1.RoleBinding {
	mrbList := make([]rbacv1.RoleBinding, 0, len(rbList))
	processedNamespaces := make(map[string]int)

	for _, rb := range rbList {
		namespace := rb.Namespace
		_, exists := processedNamespaces[namespace]
		if !exists {
			processedNamespaces[namespace] = 0
		}

		rbName := rb.Name
		if len(rb.Subjects) > 1 {
			log.Fatalf("RoleBinding %s in Namespace %s has more that one subject", rbName, namespace)
		}

		user := rb.Subjects[0].Name
		role := rb.RoleRef.Name

		if id, exists := idMap[user]; exists {
			cRole := strings.Replace(role, "appstudio", "konflux", 1)
			nrbName := strings.Replace(rbName, "appstudio", "konflux", 1)
			nrbName = strings.Replace(nrbName, user, id, 1)
			rb.Subjects[0].Name = id
			rb.RoleRef.Kind = "ClusterRole"
			rb.RoleRef.Name = cRole
			rb.Name = nrbName
			//Cleaning metadata
			rb.ObjectMeta.Annotations = nil
			rb.ObjectMeta.Labels = map[string]string{"konflux-ci.dev/type": "user"}
			rb.ObjectMeta.ResourceVersion = ""
			rb.ObjectMeta.UID = ""
			rb.ObjectMeta.CreationTimestamp = metav1.Time{}
			rb.ObjectMeta.ManagedFields = nil
			rb.APIVersion = "rbac.authorization.k8s.io/v1"
			rb.Kind = "RoleBinding"
			processedNamespaces[namespace]++
			mrbList = append(mrbList, rb)
		} else {
			// Not adding new RoleBindings for accounts not found in corporate ldap
			continue
		}
	}

	count := 0
	fmt.Printf("Searching for post-migration orphan Tenant Namespaces:\n")
	for ns, nsCount := range processedNamespaces {
		if nsCount == 0 {
			fmt.Printf("%s\n", ns)
			count++
		}
	}

	if count == 0 {
		fmt.Printf("No orphan Tenant Namespaces found\n")
	} else {
		fmt.Printf("There were %d orphan Tenant Namespaces found\n", count)
	}

	return mrbList
}

func writeMigratedRoleBindings(rbList []rbacv1.RoleBinding) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create file: %v\n", err)
	}

	defer file.Close()

	scheme := runtime.NewScheme()
	serializer := json.NewYAMLSerializer(json.DefaultMetaFactory, scheme, scheme)

	processedRBs := make(map[string]int)
	written := 0

	for _, rb := range rbList {
		//Skip if RB already processed to avoid duplicates
		processedRB := fmt.Sprintf("(%s-%s)", rb.Namespace, rb.Name)

		if _, exists := processedRBs[processedRB]; exists {
			fmt.Printf("RoleBinding %s for Namespace %s was already processed\n", rb.Name, rb.Namespace)
			continue
		}

		processedRBs[processedRB] = 1

		//writing separator ---
		_, err := file.WriteString("---\n")
		if err != nil {
			log.Printf("Failed to write separator: %v", err)
			continue
		}

		//writing RoleBinding
		yamlData, err := runtime.Encode(serializer, &rb)
		if err != nil {
			log.Printf("Failed to encode RoleBinding %s to YAML: %v\n", rb.Name, err)
			continue
		}

		//Removing creationTimestamp: null line
		cYamlData := strings.Replace(string(yamlData), "metadata:\n  creationTimestamp: null", "metadata:", 1)

		_, err = file.WriteString(cYamlData)
		if err != nil {
			log.Printf("Failed to write RoleBinding %s YAML to file: %v\n", rb.Name, err)
			continue
		}

		written++
	}

	fmt.Printf("Wrote %d migrated RoleBindings to %s\n", written, outputFile)
}

func migrate(idMap map[string]string, ctx context.Context) {
	//Load KubeConfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %v", err)
	}

	//Init k8s client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create k8s client: %v", err)
	}

	nsList := getTenantNamespaces(clientset, ctx)

	fmt.Printf("Found %d Tenant Namespaces\n", len(nsList))

	rbList := getTenantRoleBindings(clientset, ctx)

	mrbList := mutateTenantRoleBindings(idMap, rbList)

	writeMigratedRoleBindings(mrbList)
}

func init() {
	rootCmd.AddCommand(migrateCmd)

	homeDir, err := os.UserHomeDir()

	if err != nil {
		log.Fatalf("Error getting home dir: %v", err)
	}

	defaultConfig := filepath.Join(homeDir, ".kube/config")

	migrateCmd.Flags().StringVarP(&target, "target", "t", "user", "Select between 'email' and 'user' as the target identity attribute to use in RBAC")
	migrateCmd.Flags().StringVarP(&outputFile, "output-file", "o", "migrated_rolebindings.yaml", "Path to output file where migrate role bindings will be written")
	migrateCmd.Flags().StringVar(&kubeconfig, "kubeconfig", defaultConfig, "Path to the kubeconfig file")
}
