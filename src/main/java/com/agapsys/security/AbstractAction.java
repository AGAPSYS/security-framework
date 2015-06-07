/*
 * Copyright 2015 Agapsys Tecnologia Ltda-ME.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.agapsys.security;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Represents an action that will be executed only if required roles are 
 * available for execution.
 */
public abstract class AbstractAction extends RoleBasedObject {	
	
	/** 
	 * Constructor
	 * Creates an action without any required role for its execution
	 * @see RoleBasedObject#RoleBasedObject()
	 */
	public AbstractAction() {
		super();
	}
	
	/**
	 * Constructor.
	 * Creates an action with a given set of required roles.
	 * @param requiredRoles required roles for execution.
	 * @throws IllegalArgumentException if any of given roles is null
	 * @throws DuplicateException if there is an attempt to register the same role more than once (either directly of as a child of any associated role).
	 * @see RoleBasedObject#RoleBasedObject(Role...)
	 * @see AbstractAction#run(User, Object...) 
	 */
	public AbstractAction(Role...requiredRoles) throws IllegalArgumentException, DuplicateException {
		super(requiredRoles);
	}
	
	/**
	 * Constructor.
	 * Creates an action with a given set of required roles.
	 * @param requiredRoleNames required roles for execution.
	 * @throws IllegalArgumentException if any of given roles is null
	 * @throws RoleNotFoundException if any of given roleNames is not registered in {@linkplain RoleRepository}
	 * @throws DuplicateException if there is an attempt to register the same role more than once (either directly of as a child of any associated role).
	 * @see RoleBasedObject#RoleBasedObject(String...) 
	 * @see AbstractAction#run(User, Object...) 
	 */
	public AbstractAction(String...requiredRoleNames) throws IllegalArgumentException, DuplicateException, RoleNotFoundException {
		super(requiredRoleNames);
	}
	
	/** 
	 * Validates an user against action required roles.
	 * @param user {@linkplain User user} calling the action (can be null only if there are no required roles)
	 * @param params parameters passed to action
	 * @throws SecurityException if given user does not fulfill action required roles
	 */
	private void validateUser(User user, Object...params) throws SecurityException {
		Set<Role> requiredRoles = getRequiredRoles();
		
		if (user == null && !requiredRoles.isEmpty())
			throw new SecurityException(this, user, params, "Action requires an user");
		
		Set<Role> availableRoles = (user == null ? new LinkedHashSet<Role>() : user.getRoles());
		
		if (availableRoles == null)
			availableRoles = new LinkedHashSet<>();
		
		Role tmpAvailableRoles = new Role(availableRoles);
		
		if (!tmpAvailableRoles.hasChildren(requiredRoles, true)) {
			throw new SecurityException(this, user, params, "Insufficient privileges");
		}
	}
	
	/** 
	 * Called before action execution. This method will be called only if security algorithm allowed action execution. Default implementation does nothing.
	 * @param user {@linkplain User user} running this action
	 * @param params parameters passed to action on {@linkplain AbstractAction#execute(User, Object...)}
	 */
	protected void preRun(User user, Object...params) {}

	/**
	 * Actual action code. Shall be implemented by subclasses
	 * @param user {@linkplain User user} running action
	 * @param params parameters passed to action on {@linkplain AbstractAction#execute(User, Object...)}
	 */
	protected abstract void run(User user, Object...params);

	/** 
	 * Called after action execution. Default implementation does nothing 
	 * @param user {@linkplain User user} running action
	 * @param params parameters passed to action on {@linkplain AbstractAction#execute(User, Object...)}
	 */
	protected void postRun(User user, Object...params) {}
	
	/**
	 * @return A read-only set of required roles for this action execution.
	 * This is a convenience method for {@linkplain RoleBasedObject#getRoles()}
	 */
	public final Set<Role> getRequiredRoles() {
		return super.getRoles();
	}
	
	/** 
	 * Adds required roles to this action. 
	 * This is a convenience method for {@linkplain RoleBasedObject#addRole(Role...)}
	 * @param roles required roles. User running this action must have all required roles in order to proceed.
	 * @throws IllegalArgumentException if roles.length == 0 or any given role is null
	 * @throws DuplicateException if given role was already associated to this object (either directly or as child of any associated role)
	 */
	public final void addRequiredRole(Role...roles) throws DuplicateException, IllegalArgumentException {
		super.addRole(roles);
	}
	
	/** 
	 * Adds required roles to this action. 
	 * This is a convenience method for {@linkplain RoleBasedObject#addRole(String...)}
	 * @param roleNames roles to be added. Role instances will be obtained through {@linkplain RoleRepository}
	 * @throws IllegalArgumentException if roleNames.length == 0 or any of given roleNames is null/empty
	 * @throws DuplicateException if given role was already associated to this object (either directly or as child of any associated role)
	 * @throws RoleNotFoundException if any of given roleNames is not registered in {@linkplain RoleRepository}
	 */
	public final void addRequiredRole(String...roleNames) throws DuplicateException, IllegalArgumentException, RoleNotFoundException {
		super.addRole(roleNames);
	}
	
	/** 
	 * Removes a required role.
	 * This is a convenience method for {@linkplain RoleBasedObject#removeRole(Role...)}
	 * @param roles role to be removed from association set. If given role is not associated to this instance, nothing happens.
	 * @throws IllegalArgumentException if roles.length == 0 or any of given roles is null
	 */
	public final void removeRequiredRole(Role...roles) throws IllegalArgumentException {
		super.removeRole(roles);
	}
	
	/** 
	 * Removes a required role.
	 * This is a convenience method for {@linkplain RoleBasedObject#removeRole(Role...)}
	 * @param roleNames role to be removed from association set. If given role is not associated to this instance, nothing happens. Role instances will be obtained through {@linkplain RoleRepository}
	 * @throws IllegalArgumentException if roleNames.length == 0 or any given role is null/empty
	 * @throws RoleNotFoundException if any given role is not registered in {@linkplain RoleRepository}
	 */
	public final void removeRequiredRole(String...roleNames) throws IllegalArgumentException, RoleNotFoundException {
		super.removeRole(roleNames);
	}
	
	/** 
	 * Remove all required roles associations.
	 * This is a convenience method for {@linkplain RoleBasedObject#clearRoles()}
	 */
	public final void clearRequiredRoles() {		
		super.clearRoles();
	}

	/**
	 * Execute this action.
	 * @param user user calling this action. Given user must fulfill (via see {@linkplain User#getRoles()}) all required roles (see {@linkplain AbstractAction#getRequiredRoles()}) in order to execute this action
	 * @param params extra parameters passed to action execution.
	 * @throws SecurityException If user does not fulfill required roles.
	 */
	public final void execute(User user, Object...params) throws SecurityException {
		validateUser(user, params);
		preRun(user, params);
		run(user, params);
		postRun(user, params);
	}
}
