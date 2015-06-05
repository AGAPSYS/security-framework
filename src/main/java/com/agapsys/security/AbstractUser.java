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

/** Basic implementation of a {@linkplain User}. */
public class AbstractUser extends RoleBasedObject implements User {
	/** 
	 * Creates an user without any associated role.
	 * @see RoleBasedObject#RoleBasedObject()
	 */
	public AbstractUser() {
		super();
	}
	
	/**
	 * Creates an user associated with given roles
	 * @param roles associated roles
	 * @throws IllegalArgumentException if any of given roles is null
	 * @throws DuplicateException if there is an attempt to register the same role more than once (either directly of as a child of any associated role).
	 * @see RoleBasedObject#RoleBasedObject(Role...) 
	 */
	public AbstractUser(Role...roles) throws IllegalArgumentException, DuplicateException {
		super(roles);
	}
	
	/**
	 * Creates an user associated with given roles
	 * @param roles associated roles
	 * @throws IllegalArgumentException if any of given roles roles is not registered in {@linkplain RoleRepository}
	 * @throws DuplicateException if there is an attempt to register the same role more than once (either directly of as a child of any associated role).
	 * @see RoleBasedObject#RoleBasedObject(String...) 
	 */
	public AbstractUser(String...roleNames) throws IllegalArgumentException, DuplicateException {
		super(roleNames);
	}
}
