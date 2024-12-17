package fr.paris.lutece.plugins.adminauthenticationoauth2.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import fr.paris.lutece.plugins.adminauthenticationoauth2.business.authentication.AdminOauth2User;
import fr.paris.lutece.portal.business.rbac.RBACRole;
import fr.paris.lutece.portal.business.rbac.RBACRoleHome;
import fr.paris.lutece.portal.business.right.LevelHome;
import fr.paris.lutece.portal.business.right.Right;
import fr.paris.lutece.portal.business.right.RightHome;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.business.workgroup.AdminWorkgroupHome;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

/**
 * DefaultAdminOuth2UserService
 */
public class DefaultAdminOuth2UserService {

	private static final String PROPERTY_DEFAULT_RIGHTS = "adminauthenticationoauth2.default.rights.list";
	private static final String PROPERTY_DEFAULT_ADMIN_RIGHTS = "adminauthenticationoauth2.default.admin.rights.list";
	
	private static final String PROPERTY_DEFAULT_ROLES = "adminauthenticationoauth2.default.roles.list";
	private static final String PROPERTY_DEFAULT_ADMIN_ROLES = "adminauthenticationoauth2.default.admin.roles.list";
	
	private static final String PROPERTY_DEFAULT_WORKGROUPS = "adminauthenticationoauth2.default.workgroups.list";
	private static final String PROPERTY_DEFAULT_ADMIN_WORKGROUPS = "adminauthenticationoauth2.default.admin.workgroups.list";
	
	
	private static final String PROPERTY_DEFAULT_LEVEL = "adminauthenticationoauth2.default.level";
	private static final String PROPERTY_DEFAULT_ADMIN_LEVEL = "adminauthenticationoauth2.default.admin.level";
	private static final String PROPERTY_DEFAULT_ADMIN_USER_NAME = "adminauthenticationoauth2.default.admin.userName";
	
	

	private static final String[] DEFAULT_RIGHTS_LIST = AppPropertiesService.getProperty(PROPERTY_DEFAULT_RIGHTS, "")
			.split(",");
	private static final String[] DEFAULT_RIGHTS_ADMIN_LIST = AppPropertiesService.getProperty(PROPERTY_DEFAULT_ADMIN_RIGHTS, "")
			.split(",");
	
	private static final String[] DEFAULT_ROLES_LIST = AppPropertiesService.getProperty(PROPERTY_DEFAULT_ROLES, "")
			.split(",");
	private static final String[] DEFAULT_ADMIN_ROLES_LIST = AppPropertiesService.getProperty(PROPERTY_DEFAULT_ADMIN_ROLES, "")
			.split(",");
	
	
	private static final String[] DEFAULT_WORKGROUPS_LIST = AppPropertiesService
			.getProperty(PROPERTY_DEFAULT_WORKGROUPS, "").split(",");
	
	private static final String[] DEFAULT_ADMIN_WORKGROUPS_LIST = AppPropertiesService
			.getProperty(PROPERTY_DEFAULT_ADMIN_WORKGROUPS, "").split(",");
	
	
	private static final String[] DEFAULT_ADMIN_USER_NAME = AppPropertiesService
			.getProperty(PROPERTY_DEFAULT_ADMIN_USER_NAME, "").split(",");
	
	
	
	
	
	
	
	private static final int DEFAULT_LEVEL = AppPropertiesService.getPropertyInt(PROPERTY_DEFAULT_LEVEL, -1);
	private static final int DEFAULT_ADMIN_LEVEL = AppPropertiesService.getPropertyInt(PROPERTY_DEFAULT_ADMIN_LEVEL, -1);

	private static List<Right> _lstDefaultDbRights;
	private static List<RBACRole> _lstDefaultDbRoles;
	private static List<String> _lstDefaultDbWorkgroups;
	private static Integer _defaultExistingLevel;

		
	
	/**
	 * 
	 * @return Default Rights for new user
	 */
	protected static List<Right> getDefaultRights(boolean bAdmin) {
		_lstDefaultDbRights = new ArrayList<>();
		for (String strRight :  bAdmin?DEFAULT_RIGHTS_ADMIN_LIST:DEFAULT_RIGHTS_LIST) {
			Right right = RightHome.findByPrimaryKey(strRight);
			if (right != null) {
				_lstDefaultDbRights.add(right);
			}
		}
		return _lstDefaultDbRights;
	}
	/**
	 * 
	 * @return Default Roles for new user
	 */
	protected static List<RBACRole> getDefaultRoles(boolean bAdmin) {
		_lstDefaultDbRoles = new ArrayList<>();
		for (String strRole :bAdmin?DEFAULT_ADMIN_ROLES_LIST: DEFAULT_ROLES_LIST) {
			RBACRole rbacRole = RBACRoleHome.findByPrimaryKey(strRole);
			if (rbacRole != null) {
				_lstDefaultDbRoles.add(rbacRole);
			}
		}
		return _lstDefaultDbRoles;
	}

	/**
	 * @return Default Workgroups for new user
	 */
	protected static List<String> getDefaultWorkgroups(boolean bAdmin) {
		_lstDefaultDbWorkgroups = new ArrayList<>();
		for (String strWorkgroup : bAdmin?DEFAULT_ADMIN_WORKGROUPS_LIST:DEFAULT_WORKGROUPS_LIST) {
			if (AdminWorkgroupHome.checkExistWorkgroup(strWorkgroup)) {
				_lstDefaultDbWorkgroups.add(strWorkgroup);
			}
		}
		return _lstDefaultDbWorkgroups;
	}
	
	  
   /**
    * 
    * @return default level  for new user
    */
	protected static int getDefaultLevel(boolean bAdmin) {
		if (LevelHome.findByPrimaryKey(bAdmin?DEFAULT_ADMIN_LEVEL:DEFAULT_LEVEL) != null) {
			_defaultExistingLevel = bAdmin?DEFAULT_ADMIN_LEVEL:DEFAULT_LEVEL;
		} else {
			_defaultExistingLevel = -1;
		}
		return _defaultExistingLevel;
	}
	
	
	

	
	
	
	/**
	 * create user with default rights/roles/workgroups 
	 * @param user user
	 */

	public static void createUser(AdminOauth2User user) {
		
		boolean isAdmin=isAdminUser(user);
		
		if (user.getLastName() == null) {
			user.setLastName("");
		}
		if (user.getFirstName() == null) {
			user.setFirstName("");
		}
		user.setUserLevel(getDefaultLevel(isAdmin));
		AdminUserHome.create(user);

		for (RBACRole role : getDefaultRoles(isAdmin)) {
			AdminUserHome.createRoleForUser(user.getUserId(), role.getKey());
		}

		for (Right right : getDefaultRights(isAdmin)) {
			AdminUserHome.createRightForUser(user.getUserId(), right.getId());
		}

		for (String strWorkgroup : getDefaultWorkgroups(isAdmin)) {
			AdminWorkgroupHome.addUserForWorkgroup(user, strWorkgroup);
		}

		
		
		// set the rights for this user
		user.setRights(AdminUserHome.getRightsListForUser(user.getUserId()));

		// set the rights for this user
		user.setRoles(AdminUserHome.getRolesListForUser(user.getUserId()));

		// set the workgroups for this user
		user.setUserWorkgroups(getDefaultWorkgroups(isAdmin));

	}
	
	
	static boolean  isAdminUser(AdminOauth2User user)
	{
		
		return Arrays.stream(DEFAULT_ADMIN_USER_NAME).anyMatch(x-> user.getAccessCode().equals(x));
		
	}
	

}
