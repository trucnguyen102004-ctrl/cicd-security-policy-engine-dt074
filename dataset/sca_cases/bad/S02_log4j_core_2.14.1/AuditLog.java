import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuditLog {
    private static final Logger LOG = LogManager.getLogger(AuditLog.class);
    public void record(String event) { LOG.info("event={}", event); }
}
