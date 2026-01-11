// VulnerableExample.java
import org.apache.commons.collections.CollectionUtils;

import java.util.List;

public class VulnerableExample {

    public static boolean isNotEmpty(List<String> list) {
        return CollectionUtils.isNotEmpty(list);
    }
}
