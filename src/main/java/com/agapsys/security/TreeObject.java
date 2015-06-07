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

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/** Represents an object which can contains children objects. */
public class TreeObject<T extends TreeObject> implements Serializable {
	private final Set<T> children = new HashSet<>();
	private transient Set<T> readOnlyChildren;
	
	/** Constructs an empty object without any children. */
	public TreeObject() {}
	
	/** 
	 * Constructs an object with a given set of children.
	 * @param childrenSet default children to be added
	 * @throws IllegalArgumentException if children == null or children set contains null
	 */
	public TreeObject(Set<T> childrenSet) throws IllegalArgumentException {
		if (childrenSet == null)
			throw new IllegalArgumentException("Null children");
		
		if (childrenSet.contains(null))
			throw new IllegalArgumentException("Children set contains null");
		
		
		for (T child : childrenSet) {
			children.add(child);
		}
	}
	
	/** Updates read-only version of children. */
	private void updateReadOnlyChildren() {
		readOnlyChildren = Collections.unmodifiableSet(children);
	}
	
	/** @return A read-only set of children. */
	public final Set<T> getChildren() {
		if (readOnlyChildren == null)
			updateReadOnlyChildren();
		
		return readOnlyChildren;
	}
	
	/** @return A boolean indicating if this object has children. */
	public final boolean hasChildren() {
		return !children.isEmpty();
	}
	
	/** 
	 * Returns a boolean indicating if given object is a child of this object.
	 * @param child object to be tested
	 * @param recursive define if children of children shall be searched
	 * @return boolean indicating if given object was added
	 * @throws IllegalArgumentException if child == null
	 */
	public final boolean hasChild(T child, boolean recursive) throws IllegalArgumentException {
		if (child == null)
			throw new IllegalArgumentException("Null child");
		
		if (hasChildren()) {
			
			if (recursive) {
				for (TreeObject<T> tmpChild : children) {
					if (tmpChild.equals(child)) {
						return true;
					} else {
						if (tmpChild.hasChildren()) {
							if (tmpChild.hasChild(child, true)) {
								return true;
							}
						}
					}				
				}

				return false;
			} else {
				return children.contains(child);
			}
			
		} else {
			return false;
		}
	}

	/** 
	 * Returns a boolean indicating if all elements of given set are children of this element.
	 * @param childrenSet children to check
	 * @param recursive define if children of children shall be searched
	 * @return boolean indicating if all elements of given sets are children of this element. Note: a empty set is always contained in a {@linkplain TreeObject}
	 * @throws IllegalArgumentException if childrenSet is null
	 */
	public final boolean hasChildren(Set<T> childrenSet, boolean recursive) throws IllegalArgumentException {
		if (childrenSet == null)
			throw new IllegalArgumentException("Null children set");
		
		for (T t : childrenSet) {
			if (!this.hasChild(t, recursive))
				return false;
		}
		
		return true;
	}
	
	/**
	 * Returns a boolean indicating if this object is a child of given object.
	 * @param parent parent to test
	 * @param recursive define if parents of parents shall be searched
	 * @return a boolean indicating if this object is a child of given object
	 * @throws IllegalArgumentException if parent == null
	 */
	public final boolean belongsTo(T parent, boolean recursive) throws IllegalArgumentException {
		if (parent == null)
			throw new IllegalArgumentException("Null parent");
		
		return parent.hasChild(this, recursive);
	}
	
	/**
	 * Returns a boolean indicating if this objects is a child of any of the members of given set.
	 * @param parentSet parents to be searched
	 * @param recursive define if parents of parents shall be searched
	 * @return boolean with the test result
	 * @throws IllegalArgumentException if parentSet == null
	 */
	public final boolean belongsTo(Set<T> parentSet, boolean recursive) throws IllegalArgumentException {
		if (parentSet == null)
			throw new IllegalArgumentException("Null parent set");
		
		for (T t : parentSet) {
			if (t.equals(this))
				return true;
			
			if (this.belongsTo(t, recursive))
				return true;
		}
		
		return false;
	}
	
	/**
	 * Adds an object as a child.
	 * @param child child to be added
	 * @throws DuplicateException if given child was already added as a direct child of this object.
	 * @throws IllegalArgumentException if child == null
	 * @throws CircularReferenceException if child.equals(this) or children (direct or indirect) of given child equals to this
	 */
	public final void addChild(T child) throws DuplicateException, IllegalArgumentException, CircularReferenceException {
		if (child == null)
			throw new IllegalArgumentException("Null child");
		
		if (child.equals(this) || child.hasChild(this, true))
			throw new CircularReferenceException("Cannot add itself as a child: " + child.toString());
		
		if (children.contains(child))
			throw new DuplicateException("Child already added: " + child.toString());
		
		if (children.add(child)) {
			updateReadOnlyChildren();
		}
	}
	
	/**
	 * Removes a direct child. If given object is not a direct child, nothing happens.
	 * @param child child to be removed.
	 * @throws IllegalArgumentException if child == null
	 */
	public final void removeChild(T child) throws IllegalArgumentException {
		if (child == null)
			throw new IllegalArgumentException("Null child");
		
		if (children.remove(child)) {
			updateReadOnlyChildren();
		}
	}

	// CLEAR -------------------------------------------------------------------
	/** Remove all children objects. */
	public final void clearChildren() {
		if (!children.isEmpty()) {
			children.clear();
			updateReadOnlyChildren();
		}
	}	

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 47 * hash + Objects.hashCode(this.children);
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		return this == obj;
	}
}

