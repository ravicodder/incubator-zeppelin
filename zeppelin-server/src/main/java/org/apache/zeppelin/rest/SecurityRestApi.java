/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zeppelin.rest;

import com.google.common.collect.Maps;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.jndi.JndiRealmFactory;
import org.apache.shiro.realm.ldap.JndiLdapContextFactory;
import org.apache.shiro.realm.ldap.JndiLdapRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.ticket.TicketContainer;
import org.apache.zeppelin.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.*;

/**
 * Zeppelin security rest api endpoint.
 *
 */
@Path("/security")
@Produces("application/json")
public class SecurityRestApi {
  private static final Logger LOG = LoggerFactory.getLogger(SecurityRestApi.class);

  /**
   * Required by Swagger.
   */
  public SecurityRestApi() {
    super();
  }

  /**
   * Get ticket
   * Returns username & ticket
   * for anonymous access, username is always anonymous.
   * After getting this ticket, access through websockets become safe
   *
   * @return 200 response
   */
  @GET
  @Path("ticket")
  public Response ticket() {
    ZeppelinConfiguration conf = ZeppelinConfiguration.create();
    String principal = SecurityUtils.getPrincipal();
    HashSet<String> roles = SecurityUtils.getRoles();
    JsonResponse response;
    // ticket set to anonymous for anonymous user. Simplify testing.
    try {




     // SimpleAccount SA = new SimpleAccount();
      Map<String, String> userslist = new HashMap<>();
      DefaultWebSecurityManager defaultWebSecurityManager;
      String key = "org.apache.shiro.util.ThreadContext_SECURITY_MANAGER_KEY";
      defaultWebSecurityManager = (DefaultWebSecurityManager) ThreadContext.get(key);
      Collection<Realm> realms = (Collection<Realm>) defaultWebSecurityManager.getRealms();
      List realmsList = new ArrayList(realms);
      for (int i = 0; i < realmsList.size(); i++) {
        String name = realmsList.get(i).getClass().getName();
        LOG.info(name + "hello");
        if (name.equals("org.apache.shiro.realm.text.IniRealm"))
        {
          IniRealm r = (IniRealm) realmsList.get(i);
          Map<String, String> iniusers = r.getIni().get("users");
          userslist.putAll(Maps.difference(iniusers, userslist).entriesOnlyOnLeft());

        }
        else if (name.equals("org.apache.shiro.realm.ldap.JndiLdapRealm"))
        {
          JndiLdapRealm r = (JndiLdapRealm) realmsList.get(i);
          String userDnTemplate = r.getUserDnTemplate();

          String userDn[] =  userDnTemplate.split(",", 2);
          String userDnPrefix  =  userDn[0].split("=")[0];
          String userDnSuffix =  userDn[1];
          JndiLdapContextFactory CF = (JndiLdapContextFactory) r.getContextFactory();
          LdapContext ctx = CF.getSystemLdapContext();
          SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

          String[] attrIDs = {userDnPrefix
          };
          constraints.setReturningAttributes(attrIDs);
          Map<String, String> ldapusers = new HashMap<>();
          NamingEnumeration result = ctx.search(userDnSuffix , "(objectclass=*)", constraints);
          while (result.hasMore()) {
            Attributes attrs = ((SearchResult) result.next()).getAttributes();

            if (attrs.get(userDnPrefix) != null) {
              String currentUser = attrs.get(userDnPrefix).toString();
              ldapusers.put(currentUser, currentUser.split(":")[1]);
            }


          }
          userslist.putAll(Maps.difference(ldapusers, userslist).entriesOnlyOnLeft());

        }

      }
      //JndiLdapRealm r = (JndiLdapRealm) realmsList.get(0);*/

      Subject subject = org.apache.shiro.SecurityUtils.getSubject();
   /*   JndiLdapContextFactory CF = (JndiLdapContextFactory) r.getContextFactory();
      // Object cred = (Object) "hortonworks";

      LdapContext ctx = CF.getSystemLdapContext();
      SearchControls constraints = new SearchControls();
      constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
      String[] attrIDs = {"uid"
      };
      constraints.setReturningAttributes(attrIDs);
      String usersfx = "cn=users,cn=accounts,dc=hortonworks,dc=com";
      NamingEnumeration answer = ctx.search(usersfx , "(objectclass=*)", constraints);
      while (answer.hasMore()) {
        Attributes attrs = ((SearchResult) answer.next()).getAttributes();
        System.out.println( attrs.get("uid"));

      }*/

     /* SimplePrincipalCollection sp = new SimplePrincipalCollection(subject.getPrincipals());
      Set<String> S = sp.getRealmNames();
      Iterator iter = S.iterator();
      while (iter.hasNext()) {
        System.out.println(iter.next());
      }*/
    }
    catch (Exception e)
    {
      System.out.println(e);
    }
    String ticket;
    if ("anonymous".equals(principal))
      ticket = "anonymous";
    else
      ticket = TicketContainer.instance.getTicket(principal);

    Map<String, String> data = new HashMap<>();
    data.put("principal", principal);
    data.put("roles", roles.toString());
    data.put("ticket", ticket);

    response = new JsonResponse(Response.Status.OK, "", data);
    LOG.warn(response.toString());
    return response.build();
  }


  @GET
  @Path("userlist")
  public Response putUserList()
  {
    Map<String, String> userslist = new HashMap<>();
    try {

      DefaultWebSecurityManager defaultWebSecurityManager;
      String key = "org.apache.shiro.util.ThreadContext_SECURITY_MANAGER_KEY";
      defaultWebSecurityManager = (DefaultWebSecurityManager) ThreadContext.get(key);
      Collection<Realm> realms = (Collection<Realm>) defaultWebSecurityManager.getRealms();
      List realmsList = new ArrayList(realms);
      for (int i = 0; i < realmsList.size(); i++) {
        String name = realmsList.get(i).getClass().getName();
        LOG.info(name + "hello");
        if (name.equals("org.apache.shiro.realm.text.IniRealm")) {
          IniRealm r = (IniRealm) realmsList.get(i);
          Map<String, String> iniusers = r.getIni().get("users");
          userslist.putAll(Maps.difference(iniusers, userslist).entriesOnlyOnLeft());
        } else if (name.equals("org.apache.shiro.realm.ldap.JndiLdapRealm")) {
          JndiLdapRealm r = (JndiLdapRealm) realmsList.get(i);
          String userDnTemplate = r.getUserDnTemplate();
          String userDn[] = userDnTemplate.split(",", 2);
          String userDnPrefix = userDn[0].split("=")[0];
          String userDnSuffix = userDn[1];
          JndiLdapContextFactory CF = (JndiLdapContextFactory) r.getContextFactory();
          LdapContext ctx = CF.getSystemLdapContext();
          SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String[] attrIDs = {userDnPrefix
          };
          constraints.setReturningAttributes(attrIDs);
          Map<String, String> ldapusers = new HashMap<>();
          NamingEnumeration result = ctx.search(userDnSuffix, "(objectclass=*)", constraints);
          while (result.hasMore()) {
            Attributes attrs = ((SearchResult) result.next()).getAttributes();
            if (attrs.get(userDnPrefix) != null) {
              String currentUser = attrs.get(userDnPrefix).toString();
              ldapusers.put(currentUser.split(":")[1], currentUser);
            }
          }
          userslist.putAll(Maps.difference(ldapusers, userslist).entriesOnlyOnLeft());
        }
      }
      return new JsonResponse<>(Response.Status.OK, "", userslist).build();

    } catch (Exception e) {
      System.out.println(e);
      return new JsonResponse<>(Response.Status.OK, "", userslist).build();
    }
    /*DefaultWebSecurityManager defaultWebSecurityManager;
    String key = "org.apache.shiro.util.ThreadContext_SECURITY_MANAGER_KEY";
    defaultWebSecurityManager = (DefaultWebSecurityManager) ThreadContext.get(key);
    Collection<Realm> realms = (Collection<Realm>) defaultWebSecurityManager.getRealms();
    List realmsList = new ArrayList(realms);
    IniRealm r = (IniRealm) realmsList.get(0);
    Map<String, String> userslist = r.getIni().get("users");*/
    //  return new JsonResponse<>(Response.Status.OK, "", userslist).build();
  }
}
