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

/** Represents a repository of roles for an application. */
public class RoleRepository extends NamedObjectRepository<Role> {
	// CLASS SCOPE =============================================================
	private static final RoleRepository singleton = new RoleRepository();
	
	/** @return A singleton instance for this application. */
	public static RoleRepository getSingletonInstance() {
		return singleton;
	}
	// =========================================================================
	
	// INSTANCE SCOPE ==========================================================	
	/** Private constructor (prevents external instantiation). */
	private RoleRepository() {}
	
	/** 
	 * Creates a role and adds it this repository
	 * @param roleName name of the role to be created. Must be unique in the repository
	 * @return created role
	 * @throws DuplicateException if a role with the same name was already created
	 * @throws IllegalArgumentException if (roleName == null || roleName.isEmpty())
	 */
	public Role createRole(String roleName) throws IllegalArgumentException, DuplicateException {
		if (get(roleName) != null)
			throw new DuplicateException("An object with the same name is already registered: " + roleName);
		
		Role role = new Role(roleName);
		add(role);
		
		return role;
	}
	
	/**
	 * Gets a role from this repository or creates a new one if there is no such role
	 * @param roleName role to be obtained/created
	 * @return role instance
	 * @throws IllegalArgumentException if (roleName == null || roleName.isEmpty())
	 */
	public Role getOrCreate(String roleName) throws IllegalArgumentException {
		if (roleName == null || roleName.isEmpty())
			throw new IllegalArgumentException("Null/Empty roleName");
		
		Role role = get(roleName);
		
		if (role == null) {
			role = createRole(roleName);
		}
		
		return role;
	}
}
