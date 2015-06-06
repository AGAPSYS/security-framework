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

package com.agapsys.security.test;

import com.agapsys.security.TreeObject;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.Test;
import static org.junit.Assert.*;

public class TreeObjectTest {
	// CLASS SCOPE =============================================================
	private class TestTreeObject extends TreeObject<TestTreeObject> {
		private final String name;
		
		public TestTreeObject() {
			name = null;
		}
		
		public TestTreeObject(String name) {
			if (name == null || name.isEmpty())
				throw new IllegalArgumentException("Null/Empty name");
			
			this.name = name;
		}
		
		@Override
		public String toString() {
			return name == null ? super.toString() : String.format("%s (%s)", name, super.toString());
		}
	}

	private Set<TestTreeObject> getSet(TestTreeObject...objects) {
		Set<TestTreeObject> set = new LinkedHashSet<>();
		
		set.addAll(Arrays.asList(objects));
		
		return set;
	}
	// =========================================================================
	
	// INSTANCE SCOPE ==========================================================
	@Test
	public void getChildren() {
		TestTreeObject testObject = new TestTreeObject();
		
		assertFalse(testObject.hasChildren());
		
		testObject.addChild(new TestTreeObject());
		
		assertTrue(testObject.hasChildren());
	}
	
	@Test
	public void hasChildren() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.hasChildren());
		assertTrue(root1Child1.hasChildren());
		assertFalse(root1Child1Child.hasChildren());
		assertFalse(root1Child2.hasChildren());
		assertFalse(root2.hasChildren());
	}
	
	@Test
	public void addItself()  {
		try {
			TestTreeObject testObject = new TestTreeObject();
			testObject.addChild(testObject);
		} catch (IllegalArgumentException ex) {
			assertTrue(ex.getMessage().contains("itself"));
		}
	}
	
	// testHasChild ------------------------------------------------------------
	@Test
	public void directHasChild() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.hasChild(root1Child1, false));
		assertTrue(root1.hasChild(root1Child2, false));
		assertFalse(root1.hasChild(root1Child1Child, false));
		assertFalse(root1.hasChild(root2, false));
	}
	
	@Test
	public void recursiveHasChild() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.hasChild(root1Child1, true));
		assertTrue(root1.hasChild(root1Child2, true));
		assertTrue(root1.hasChild(root1Child1Child, true));
		assertFalse(root1.hasChild(root2, true));
	}
	// -------------------------------------------------------------------------
	
	// testHasChildrenSet ------------------------------------------------------	
	@Test
	public void directHasChildrenSet() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.hasChildren(getSet(root1Child1, root1Child2), false));
		assertFalse(root1.hasChildren(getSet(root1Child1, root1Child2, root1Child1Child), false));
		assertTrue(root1.hasChildren(getSet(), false));
		assertTrue(root2.hasChildren(getSet(), false));
	}
	
	@Test
	public void recursiveHasChildrenSet() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.hasChildren(getSet(root1Child1, root1Child2), true));
		assertTrue(root1.hasChildren(getSet(root1Child1, root1Child2, root1Child1Child), true));
		assertTrue(root1.hasChildren(getSet(), true));
		assertTrue(root2.hasChildren(getSet(), true));
	}
	// -------------------------------------------------------------------------
	
	// testBelongsTo -----------------------------------------------------------
	@Test
	public void directBelongsTo() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertFalse(root1Child1Child.belongsTo(root1, false));
		assertTrue(root1Child1.belongsTo(root1, false));
		assertTrue(root1Child2.belongsTo(root1, false));
		
		assertTrue(root1Child1Child.belongsTo(root1Child1, false));
		assertFalse(root2.belongsTo(root1, false));
	}
	
	@Test
	public void recursiveBelongsTo() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1Child1Child.belongsTo(root1, true));
		assertTrue(root1Child1.belongsTo(root1, true));
		assertTrue(root1Child2.belongsTo(root1, true));
		assertTrue(root1Child1Child.belongsTo(root1Child1, true));
		assertFalse(root2.belongsTo(root1, true));
	}
	// -------------------------------------------------------------------------

	// testBelongsToSet --------------------------------------------------------
	@Test
	public void directBelongsToSet() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.belongsTo(getSet(root1), false));
		assertTrue(root1Child1.belongsTo(getSet(root1, root2), false));
		assertFalse(root1Child1Child.belongsTo(getSet(root1, root2), false));
	}
	
	@Test
	public void recursiveBelongsToSet() {
		TestTreeObject root1 = new TestTreeObject("ROOT1");
		TestTreeObject root1Child1 = new TestTreeObject("ROOT1/CHILD1");
		TestTreeObject root1Child1Child = new TestTreeObject("ROOT1/CHILD1/CHILD");
		TestTreeObject root1Child2 = new TestTreeObject("ROOT1/CHILD2");
		TestTreeObject root2 = new TestTreeObject("ROOT2");
		
		root1Child1.addChild(root1Child1Child);
		root1.addChild(root1Child1);
		root1.addChild(root1Child2);
		
		assertTrue(root1.belongsTo(getSet(root1), true));
		assertTrue(root1Child1.belongsTo(getSet(root1, root2), true));
		assertTrue(root1Child1Child.belongsTo(getSet(root1, root2), true));
	}
	// -------------------------------------------------------------------------
	// =========================================================================
}
