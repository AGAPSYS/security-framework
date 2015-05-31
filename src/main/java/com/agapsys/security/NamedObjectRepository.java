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

import java.util.LinkedHashMap;
import java.util.Map;

/** Represents a repository of {@linkplain NamedObject}s. */
public class NamedObjectRepository<T extends NamedObject> {
	private final Map<String, T> map = new LinkedHashMap<>();

	/** Constructor. */
	public NamedObjectRepository() {}
	
	/** 
	 * Adds an object to this repository.
	 * @param t object to be added
	 * @throws IllegalArgumentException if given object is null or given object haves an empty/null name
	 * @throws DuplicateException if an object with the same name was already added to this repository
	 */
	public void add(T t) throws IllegalArgumentException, DuplicateException {
		if (t == null)
			throw new IllegalArgumentException("Null object");
		
		String name = t.getName();
		
		if (name == null || name.isEmpty())
			throw new IllegalArgumentException("Null/Empty name");
		
		if (map.containsKey(name))
			throw new DuplicateException("An object with the same name was already added: " + name);

		map.put(name, t);
	}
	
	/** 
	 * Removes an object with given name from this repository.
	 * If there is no such object, nothing happens.
	 * @throws IllegalArgumentException if objName is null or empty
	 */
	public void remove(String objName) throws IllegalArgumentException {
		if (objName == null || objName.isEmpty())
			throw new IllegalArgumentException("Null/Empty name");
		
		map.remove(objName);
	}
	
	/**
	 * Returns an object with given name from this repository.
	 * If there is no such object, returns null.
	 * @throws IllegalArgumentException if objName is null or empty
	 */
	public T get(String objName) throws IllegalArgumentException {
		if (objName == null || objName.isEmpty())
			throw new IllegalArgumentException("Null/Empty name");
		
		return map.get(objName);
	}

	/** Clear this repository. */
	public void clear() {
		map.clear();
	}

	/** Returns a boolean indicating if an object with given name is registered .*/
	public boolean contains(String objName) {
		return map.containsKey(objName);
	}
}
