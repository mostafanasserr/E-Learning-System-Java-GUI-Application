package javasemesterproject.security.logging;

/**
 * Abstract Factory contract for producing loggers.
 *
 * Concrete factories ({@link SecureLoggerFactory}, {@link ProductionLoggerFactory})
 * decide which Logger implementation to return, allowing the client
 * ({@code Processor}) to remain decoupled from the concrete logger.
 */
public interface LoggerFactory {

    /**
     * @return a fully-initialised logger ready to record events.
     */
    Logger getLogger();
}
