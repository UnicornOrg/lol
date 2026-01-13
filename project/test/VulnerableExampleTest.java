import org.junit.Test;
import org.junit.Assert;

import java.util.ArrayList;
import java.util.List;

/**
 * Test class for VulnerableExample to verify functionality after upgrading
 * Apache Commons Collections from 3.2.1 to 4.4 (commons-collections4).
 *
 * This test suite validates:
 * 1. The isNotEmpty method works correctly with the new package
 * 2. Empty and null list handling
 * 3. Non-empty list detection
 * 4. Compatibility with the upgraded commons-collections4 library
 */
public class VulnerableExampleTest {

    /**
     * Test that isNotEmpty returns false for null list
     */
    @Test
    public void testIsNotEmpty_NullList() {
        List<String> nullList = null;
        boolean result = VulnerableExample.isNotEmpty(nullList);
        Assert.assertFalse("isNotEmpty should return false for null list", result);
    }

    /**
     * Test that isNotEmpty returns false for empty list
     */
    @Test
    public void testIsNotEmpty_EmptyList() {
        List<String> emptyList = new ArrayList<>();
        boolean result = VulnerableExample.isNotEmpty(emptyList);
        Assert.assertFalse("isNotEmpty should return false for empty list", result);
    }

    /**
     * Test that isNotEmpty returns true for list with one element
     */
    @Test
    public void testIsNotEmpty_SingleElement() {
        List<String> singleElementList = new ArrayList<>();
        singleElementList.add("element");
        boolean result = VulnerableExample.isNotEmpty(singleElementList);
        Assert.assertTrue("isNotEmpty should return true for list with one element", result);
    }

    /**
     * Test that isNotEmpty returns true for list with multiple elements
     */
    @Test
    public void testIsNotEmpty_MultipleElements() {
        List<String> multiElementList = new ArrayList<>();
        multiElementList.add("first");
        multiElementList.add("second");
        multiElementList.add("third");
        boolean result = VulnerableExample.isNotEmpty(multiElementList);
        Assert.assertTrue("isNotEmpty should return true for list with multiple elements", result);
    }

    /**
     * Test that verifies the upgraded commons-collections4 library is functioning
     * correctly after migration from the vulnerable 3.2.1 version.
     * This ensures backward compatibility of CollectionUtils.isNotEmpty() method.
     */
    @Test
    public void testCommonsCollections4Compatibility() {
        // Test with various list states to ensure complete compatibility
        List<String> testList = new ArrayList<>();

        // Initially empty
        Assert.assertFalse("Should be false for empty list",
            VulnerableExample.isNotEmpty(testList));

        // After adding element
        testList.add("test");
        Assert.assertTrue("Should be true after adding element",
            VulnerableExample.isNotEmpty(testList));

        // After clearing
        testList.clear();
        Assert.assertFalse("Should be false after clearing list",
            VulnerableExample.isNotEmpty(testList));
    }
}
