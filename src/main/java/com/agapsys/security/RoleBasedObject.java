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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** Represents an object with association to roles. */
public abstract class RoleBasedObject {
	private final Set<Role> roles = new LinkedHashSet<>();
	private Set<Role> readOnlyRoles = null;
	
	/**
	 * Constructor.
	 * Creates an object without any associated role.
	 */
	public RoleBasedObject() {}
	
	/**
	 * Constructor.
	 * @param roles default roles associated to this object
	 * @throws IllegalArgumentException if any of the following conditions occurs:
	 * <ul>
	 *		<li>roles == null</li>
	 *		<li>any of given roles is null</li>
	 * </ul>
	 * @throws DuplicateException if any of given roles is already associated to this object (either directly of as a child of any associated role).
	 */
	public RoleBasedObject(Role...roles) throws IllegalArgumentException, DuplicateException {
		if (roles == null)
			throw new IllegalArgumentException("Null roles");
		
		for (Role role : roles) {
			addIndividualRole(role);
		}
	}
	
	/**
	 * Constructor.
	 * @param roleNames default role names associated to this object. Role 
	 * instances will be obtained through {@linkplain RoleRepository}
	 * @throws IllegalArgumentException if any of the following conditions occurs:
	 * <ul>
	 *		<li>roleNames == null</li>
	 *		<li>any of given roles roles is not registered in {@linkplain RoleRepository}</li>
	 * </ul>
	 * @throws DuplicateException if any of given roles is already associated to this object (either directly of as a child of any associated role).
	 */
	public RoleBasedObject(String...roleNames) throws IllegalArgumentException, DuplicateException  {
		if (roleNames == null)
			throw new IllegalArgumentException("Null roleNames");
		
		for (String roleName : roleNames) {
			Role role = RoleRepository.getSingletonInstance().get(roleName);
			
			if (role == null)
				throw new IllegalArgumentException("Role not found: " + roleName);
			
			addIndividualRole(role);
		}
	}
	
	/**
	 * Adds an individual role to associated role set.
	 * @param role role to be added
	 * @return a boolean indicating if given role was added to associated role set
	 * @throws DuplicateException if given role was already associated to this object (either directly or as child of any associated role)
	 * @throws IllegalArgumentException if given role is null
	 */
	private boolean addIndividualRole(Role role) throws DuplicateException, IllegalArgumentException {
		if (role == null)
			throw new IllegalArgumentException("Null role");
	
		for (Role tmpRole : this.roles) {
			if (tmpRole.equals(role) || tmpRole.hasChild(role, true)) {
				if (tmpRole.equals(role)) {
					throw new DuplicateException("Role already added: " + role);
				} else {
					throw new DuplicateException(String.format("Role (%s) already added as a child of %s", role, tmpRole));
				}
			}
		}
		return this.roles.add(role);
	}
	
	/** Updates internal read-only set. */
	private void updateReadOnlyRoles() {
		readOnlyRoles = Collections.unmodifiableSet(roles);
	}
	
	/** Returns a read-only set of roles associated to this instance. */
	public Set<Role> getRoles() {
		if (readOnlyRoles == null)
			updateReadOnlyRoles();
		
		return readOnlyRoles;
	}

	/** 
	 * Associates given roles to this object
	 * @param roles to be associated
	 * @throws IllegalArgumentException if any of given conditions occurs:
	 * <ul>
	 *		<li>roles==null</li>
	 *		<li>roles.length == 0</li>
	 *		<li>any role given roles elements is null</li>
	 * </ul>
	 * @throws DuplicateException if given role was already associated to this object (either directly or as child of any associated role)
	 */
	public void addRole(Role...roles) throws DuplicateException, IllegalArgumentException {
		if (roles == null || roles.length == 0)
			throw new IllegalArgumentException("Null/Empty roles");
		
		boolean update = false;
		for (Role role : roles) {
			update = addIndividualRole(role);
		}
		
		if (update)
			updateReadOnlyRoles();
	}
	
	/** 
	 * Associates a role to this instance.
	 * @param roleNames roles to be added. Role instances will be obtained through {@linkplain RoleRepository}
	 * @throws IllegalArgumentException if any of given conditions occurs:
	 * <ul>
	 *		<li>roleNames==null</li>
	 *		<li>roleNames.length == 0</li>
	 *		<li>any of given roles roles is not registered in {@linkplain RoleRepository}</li>
	 * </ul>
	 * @throws DuplicateException if given role was already associated to this object (either directly or as child of any associated role)
	 */
	public void addRole(String...roleNames) throws DuplicateException, IllegalArgumentException {
		if (roleNames == null || roleNames.length == 0)
			throw new IllegalArgumentException("Null/Empty roleNames");
		
		boolean update = false;
		
		for (String roleName : roleNames) {
			Role role = RoleRepository.getSingletonInstance().get(roleName);
			
			if (role == null)
				throw new IllegalArgumentException("Role not found: " + roleName);
			
			update = addIndividualRole(role);
		}
		
		if (update)
			updateReadOnlyRoles();
	}
	
	/**
	 * Removes the association of a role with this instance.
	 * @param roles role to be removed from association set. If given role is not
	 * associated to this instance, nothing happens.
	 * @throws roles if roles == null or roles.length == 0 or any of given roles == null
	 */
	public void removeRole(Role...roles) throws IllegalArgumentException {
		if (roles == null || roles.length == 0)
			throw new IllegalArgumentException("Null/Empty roles");
		
		boolean update = false;
		
		for (Role role : roles) {
			if (role == null)
				throw new IllegalArgumentException("Null role");
			
			update = this.roles.remove(role);
		}
		
		if (update)
			updateReadOnlyRoles();
	}
	
	/**
	 * Removes the association of a role with this instance.
	 * @param roleNames role to be removed from association set. If given role is not
	 * associated to this instance, nothing happens. Role instances will be obtained through {@linkplain RoleRepository}
	 * @throws roles if roles == null or roles.length == 0 or any of given roles is not registered in {@linkplain RoleRepository}
	 */
	public void removeRole(String...roleNames) throws IllegalArgumentException {
		if (roleNames == null || roleNames.length == 0)
			throw new IllegalArgumentException("Null/Empty roleNames");
		
		boolean update = false;
		
		for (String roleName : roleNames) {
			Role role = RoleRepository.getSingletonInstance().get(roleName);
			
			if (role == null)
				throw new IllegalArgumentException("Role not found: " + roleName);
			
			update = this.roles.remove(role);
		}
		
		if (update)
			updateReadOnlyRoles();
	}
	
	/** Removes all role associations. */
	public void clearRoles() {
		if (roles.size() > 0) {
			roles.clear();
			updateReadOnlyRoles();
		}
	}
}
