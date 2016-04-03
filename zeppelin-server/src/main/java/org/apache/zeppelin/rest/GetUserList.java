package org.apache.zeppelin.rest;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.ldap.JndiLdapContextFactory;
import org.apache.shiro.realm.ldap.JndiLdapRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.util.JdbcUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.*;

/**
 * Created by raviranjan on 31/03/16.
 */
public class GetUserList {

  List<String> userlist = new ArrayList<>();
  private static final Logger LOG = LoggerFactory.getLogger(GetUserList.class);
  public List<String> getUserList(IniRealm r) {
    List<String> userlist = new ArrayList<>();
    Map getIniUser = new HashMap();
    getIniUser = r.getIni().get("users");
    Iterator it = getIniUser.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry pair = (Map.Entry) it.next();
      userlist.add(pair.getKey().toString());
    }
    return userlist;
  }

  public List<String> getUserList(JndiLdapRealm r) {
    List<String> userlist = new ArrayList<>();
    String userDnTemplate = r.getUserDnTemplate();
    String userDn[] =  userDnTemplate.split(",", 2);
    String userDnPrefix  =  userDn[0].split("=")[0];
    String userDnSuffix =  userDn[1];
    JndiLdapContextFactory CF = (JndiLdapContextFactory) r.getContextFactory();
    LdapContext ctx = null;
    try {
      ctx = CF.getSystemLdapContext();
      SearchControls constraints = new SearchControls();
      constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
      String[] attrIDs = { userDnPrefix };
      constraints.setReturningAttributes(attrIDs);
      NamingEnumeration result = ctx.search(userDnSuffix, "(objectclass=*)", constraints);
      while (result.hasMore()) {
        Attributes attrs = ((SearchResult) result.next()).getAttributes();
        if (attrs.get(userDnPrefix) != null) {
          String currentUser = attrs.get(userDnPrefix).toString();
          userlist.add(currentUser.split(":")[1]);
        }
      }
    }
    catch (Exception e) {
      LOG.error("Error retrieving User list from Ldap Realm", e);
    }
    return userlist;
  }

  public List<String> getUserList(JdbcRealm obj) {
    List<String> userlist = new ArrayList<>();
    PreparedStatement ps = null;
    ResultSet rs = null;
    DataSource dataSource = null;
    String userquery = "select username from users";
    try {
      dataSource = (DataSource) FieldUtils.readField(obj, "dataSource", true);
    } catch (IllegalAccessException e) {
      return null;
    }
    try {
      Connection con = dataSource.getConnection();
      ps = con.prepareStatement(userquery);
      rs = ps.executeQuery();
      while (rs.next()) {
        userlist.add(rs.getString(1));
      }
    } catch (Exception e) {
      LOG.error("Error retrieving User list from JDBC Realm", e);
    } finally {
      JdbcUtils.closeResultSet(rs);
      JdbcUtils.closeStatement(ps);
    }
    return userlist;
  }

}





