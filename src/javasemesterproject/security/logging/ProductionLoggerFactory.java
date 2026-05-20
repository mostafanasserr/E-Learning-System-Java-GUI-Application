package javasemesterproject.security.logging;

/**
 * Concrete factory returning a {@link ProductionLogger}.
 *
 * Demonstrates the second leg of the Factory pattern: same {@link LoggerFactory}
 * interface, different concrete product. The client never knows which one
 * it received and never has to change when a new logger type is added.
 */
public final class ProductionLoggerFactory implements LoggerFactory {

    private static volatile ProductionLoggerFactory INSTANCE;
    private final ProductionLogger logger;

    private ProductionLoggerFactory() {
        this.logger = new ProductionLogger();
    }

    public static ProductionLoggerFactory getInstance() {
        ProductionLoggerFactory ref = INSTANCE;
        if (ref == null) {
            synchronized (ProductionLoggerFactory.class) {
                ref = INSTANCE;
                if (ref == null) {
                    INSTANCE = ref = new ProductionLoggerFactory();
                }
            }
        }
        return ref;
    }

    @Override
    public Logger getLogger() {
        return logger;
    }
}
