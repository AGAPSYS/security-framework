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
	 * Creates an action without required roles
	 * @see RoleBasedObject#RoleBasedObject()
	 */
	public AbstractAction() {
		super();
	}
	
	/**
	 * Constructor.
	 * Creates an action with a given set of required roles.
	 * @param requiredRoles required roles for execution. If any of the required
	 * roles are not satisfied during action execution an exception will be 
	 * thrown.
	 * @throws IllegalArgumentException if any of given roles is null
	 * @throws DuplicateException if there is an attempt to register the same role more than once (either directly of as a child of any associated role).
	 * @see RoleBasedObject#RoleBasedObject(Role...)
	 * @see AbstractSecuredAction#run(User, Object...) 
	 */
	public AbstractAction(Role...requiredRoles) throws IllegalArgumentException, DuplicateException {
		super(requiredRoles);
	}
	
	/**
	 * Constructor.
	 * Creates an action with a given set of required roles.
	 * @param requiredRoleNames required roles for execution. If any of required roles
	 * are not available during action execution an exception will be thrown. Instances
	 * will be obtained through {@linkplain RoleRepository}
	 * @throws IllegalArgumentException if any of given roles roles is not registered in {@linkplain RoleRepository}
	 * @throws DuplicateException if there is an attempt to register the same role more than once (either directly of as a child of any associated role).	 * @see RoleBasedObject#RoleBasedObject(String...) 
	 * @see AbstractSecuredAction#run(User, Object...) 
	 */
	public AbstractAction(String...requiredRoleNames) throws IllegalArgumentException, DuplicateException {
		super(requiredRoleNames);
	}
	
	/** 
	 * Validates an user against action required roles.
	 * @param user user calling the action (can be null only if there are no required roles)
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
	
	/** Called before action execution (will be called only if security allowed user to proceed). Default implementation does nothing. */
	protected void preRun(User user, Object...params) {}

	/** Actual action code. */
	protected abstract void run(User user, Object...params);

	/** Called after run. Default implementation does nothing */
	protected void postRun(User user, Object...params) {}
	
	
	/**
	 * Returns a read-only set of required roles for this action execution.
	 * This is a convenience method for {@linkplain RoleBasedObject#getRoles()}
	 */
	public final Set<Role> getRequiredRoles() {
		return super.getRoles();
	}
	
	/** 
	 * Adds required roles to this action. 
	 * This is a convenience method for {@linkplain RoleBasedObject#addRole(Role...)}
	 */
	public final void addRequiredRole(Role...roles) throws DuplicateException, IllegalArgumentException {
		super.addRole(roles);
	}
	
	/** 
	 * Adds required roles to this action. 
	 * This is a convenience method for {@linkplain RoleBasedObject#addRole(String...)}
	 */
	public final void addRequiredRole(String...roleNames) throws DuplicateException, IllegalArgumentException {
		super.addRole(roleNames);
	}
	
	/** 
	 * Removes a required role.
	 * This is a convenience method for {@linkplain RoleBasedObject#removeRole(Role...)}
	 */
	public final void removeRequiredRole(Role...roles) throws IllegalArgumentException {
		super.removeRole(roles);
	}
	
	/** 
	 * Removes a required role.
	 * This is a convenience method for {@linkplain RoleBasedObject#removeRole(Role...)}
	 */
	public final void removeRequiredRole(String...roleNames) throws IllegalArgumentException {
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
	 * @param user user calling this action.
	 * If any of required roles are not satisfied, a {@linkplain SecurityException}  will be throw.
	 * @param params extra parameters passed to action execution.
	 * @throws SecurityException if any of required roles are not satisfied. If action does not have required roles, is allowed to pass a null user.
	 */
	public final void execute(User user, Object...params) throws SecurityException {
		validateUser(user, params);
		preRun(user, params);
		run(user, params);
		postRun(user, params);
	}
}
