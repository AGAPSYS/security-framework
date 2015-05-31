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

import java.util.Objects;
import java.util.Set;

/** Represents an role. */
public final class Role extends TreeObject<Role> implements NamedObject {
	private final String name;
		
	/**
	 * Constructor.
	 * @param children set of children elements.
	 * @throws IllegalArgumentException if children == null
	 */
	Role(Set<Role> children) throws IllegalArgumentException {
		super(children);
		name = null;
	}
	
	/**
	 * Constructor.
	 * @param name name associated with this instance.
	 * @throws IllegalArgumentException if name is null or name is empty
	 */
	Role(String name) throws IllegalArgumentException {
		super();
		
		if (name == null || name.isEmpty())
			throw new IllegalArgumentException("Null/Empty name");

		this.name = name;
	}
	
	/**
	 * Constructor.
	 * @param name name associated with this instance. 
	 * @param children set of children elements.
	 * @throws IllegalArgumentException if children is null of name == null or name.isEmpty()
	 */
	Role(String name, Set<Role> children) throws IllegalArgumentException {
		super(children);
		
		if (name == null || name.isEmpty())
			throw new IllegalArgumentException("Null/Empty name");

		this.name = name;
	}
	
	/**
	 * Adds an individual role as a child of this instance.
	 * @param children set of roles to test for duplications
	 * @param role role to be added
	 * @throws DuplicateException if given role was already added as a child (direct of indirect) of this instance
	 * @throws IllegalArgumentException if role==null
	 */
	private void addInvidualRole(Set<Role> children, Role role) throws DuplicateException, IllegalArgumentException {
		if (role == null)
			throw new IllegalArgumentException("Null role");
		
		for (Role child : children) {
			if (child.equals(role) || child.hasChild(role, true)) {
				String msgPattern = "Role (%s) already added as child of %s";
				if (child.equals(role)) {
					throw new DuplicateException(String.format(msgPattern, role.toString(), this.toString()));
				} else {
					throw new DuplicateException(String.format(msgPattern, role.toString(), child.toString()));
				}
			}
		}
		super.addChild(role);
	}
	
	/**
	 * Adds given roles as children of this object
	 * @param roles roles to be added
	 * @throws IllegalArgumentException if any of given conditions occurs:
	 * <ul>
	 *		<li>roles==null</li>
	 *		<li>roles.length == 0</li>
	 *		<li>any role given roles elements is null</li>
	 * </ul>
	 * @throws DuplicateException if any of given roles was already added as a child (direct of indirect) of this instance
	 */
	public final void addChild(Role...roles) throws IllegalArgumentException, DuplicateException {
		if (roles == null || roles.length == 0)
			throw new IllegalArgumentException("Null/Empty roles");
		
		Set<Role> children = getChildren();
		for (Role role : roles) {
			addInvidualRole(children, role);
		}
	}
	
	/** 
	 * Adds children roles to this instance.
	 * Children instance will be obtained through {@linkplain RoleRepository}.
	 * @param roleNames name of the roles used to obtain instances
	 * @throws IllegalArgumentException if any of given conditions occurs:
	 * <ul>
	 *		<li>roleNames==null</li>
	 *		<li>roleNames.length == 0</li>
	 *		<li>any role given roles elements is null or not exists</li>
	 * </ul>
	 * @throws DuplicateException if any of given roles was already added as a child (direct of indirect) of this instance
	 */
	public final void addChild(String...roleNames) throws DuplicateException, IllegalArgumentException {
		if (roleNames == null || roleNames.length == 0)
			throw new IllegalArgumentException("Null/Emtpry roleNames");

		Set<Role> children = getChildren();
		for (String roleName : roleNames) {
			Role role = RoleRepository.getSingletonInstance().get(roleName);
			if (role == null)
				throw new IllegalArgumentException("Role not found: " + roleName);
			
			addInvidualRole(children, role);
		}
	}

	@Override
	public String getName() {
		return name;
	}	
	
	@Override
	public int hashCode() {
		int hash = 7;
		hash = 89 * hash + Objects.hashCode(getChildren());
		hash = 89 * hash + Objects.hashCode(this.name);
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final Role other = (Role) obj;
		
		return (Objects.equals(this.getChildren(), other.getChildren()) && Objects.equals(this.name, other.name));
	}
	
	@Override
	public String toString() {
		return name == null ? super.toString() : name;
	}
}
