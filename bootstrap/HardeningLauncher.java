import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class HardeningLauncher {
    private static final String VERSION = "1.2.0";
    private static final String ARCHIVE_NAME = "hardening-gradle-plugin-1.2.0-portable-maven.zip";
    private static final String RELEASE_URL =
        "https://github.com/HolinB/android-hardening-gradle-plugin/releases/download/v1.2.0/" + ARCHIVE_NAME;
    private static final String RELEASE_SHA256 =
        "60805aa517119940a7f0458249827c1cbbbcea4eab7bc01d8d7ebd5b90eb20cf";
    private static final String MARKER =
        "repository/com/holin/android/hardening/hardening-gradle-plugin/1.2.0/" +
            "hardening-gradle-plugin-1.2.0.jar";
    private static final Pattern WRAPPER_VERSION =
        Pattern.compile("(?:^|/)gradle-([0-9]+(?:\\.[0-9]+){1,2})-(?:bin|all)\\.zip(?:$|[?#])");
    private static final Pattern CHECKSUM_LINE = Pattern.compile("([0-9a-f]{64})  (.+)");

    private HardeningLauncher() {
    }

    public static void main(String[] arguments) {
        int exitCode;
        try {
            exitCode = run(List.of(arguments), System.getenv());
        } catch (LauncherFailure failure) {
            System.err.println("hardeningw: " + failure.getMessage());
            exitCode = 2;
        } catch (Exception failure) {
            System.err.println("hardeningw: " + failure.getClass().getSimpleName() + ": " + failure.getMessage());
            exitCode = 2;
        }
        System.exit(exitCode);
    }

    private static int run(List<String> arguments, Map<String, String> environment) throws Exception {
        if (arguments.equals(List.of("--version"))) {
            System.out.println(VERSION);
            return 0;
        }
        ParsedArguments parsed = ParsedArguments.parse(arguments);
        require(Runtime.version().feature() >= 17, "JDK 17 or newer is required");
        validateConsumer(parsed.projectDirectory(), environment);

        Path cacheHome = cacheHome(environment);
        Path versionRoot = cacheHome.resolve(VERSION);
        boolean interrupted = false;
        try {
            if (!validRepository(versionRoot)) {
                interrupted = prepareRepository(cacheHome, versionRoot, parsed.offline(), environment);
            }
            require(validRepository(versionRoot), "portable repository cache is incomplete after preparation");
            return runConsumer(parsed, versionRoot.resolve("repository"), environment);
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static void validateConsumer(Path project, Map<String, String> environment) throws IOException {
        require(Files.isDirectory(project), "consumer project does not exist: " + project);
        Path wrapper = project.resolve(isWindows() ? "gradlew.bat" : "gradlew");
        require(Files.isRegularFile(wrapper), "consumer Gradle wrapper is missing: " + wrapper);
        Path properties = project.resolve("gradle/wrapper/gradle-wrapper.properties");
        require(Files.isRegularFile(properties), "consumer Gradle wrapper properties are missing");
        Properties wrapperProperties = new Properties();
        try (InputStream input = Files.newInputStream(properties)) {
            wrapperProperties.load(input);
        }
        String distributionUrl = wrapperProperties.getProperty("distributionUrl");
        require(distributionUrl != null && !distributionUrl.isBlank(),
            "consumer Gradle wrapper distributionUrl is missing");
        Matcher matcher = WRAPPER_VERSION.matcher(distributionUrl);
        require(matcher.find(), "consumer Gradle wrapper distributionUrl is unsupported");
        require(compareVersions(matcher.group(1), "8.10") >= 0,
            "consumer Gradle version is incompatible: actual=" + matcher.group(1) + ", minimum=8.10");

        Path sdk = resolveAndroidSdk(project, environment);
        require(Files.isDirectory(sdk), "Android SDK directory is missing: " + sdk);
        require(Files.isDirectory(sdk.resolve("build-tools")), "Android SDK build-tools are missing: " + sdk);
        require(Files.isDirectory(sdk.resolve("platform-tools")), "Android SDK platform-tools are missing: " + sdk);
    }

    private static Path resolveAndroidSdk(Path project, Map<String, String> environment) throws IOException {
        String configured = firstNonBlank(environment.get("ANDROID_SDK_ROOT"), environment.get("ANDROID_HOME"));
        if (configured != null) return Path.of(configured).toAbsolutePath().normalize();
        Path localProperties = project.resolve("local.properties");
        require(Files.isRegularFile(localProperties),
            "Android SDK is not configured; set ANDROID_SDK_ROOT or sdk.dir in local.properties");
        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(localProperties)) {
            properties.load(input);
        }
        String sdkDirectory = properties.getProperty("sdk.dir");
        require(sdkDirectory != null && !sdkDirectory.isBlank(), "local.properties does not contain sdk.dir");
        return Path.of(sdkDirectory).toAbsolutePath().normalize();
    }

    private static Path cacheHome(Map<String, String> environment) {
        String explicit = environment.get("HARDENING_CACHE_HOME");
        if (explicit != null && !explicit.isBlank()) return Path.of(explicit).toAbsolutePath().normalize();
        String gradleHome = environment.get("GRADLE_USER_HOME");
        Path base = gradleHome == null || gradleHome.isBlank()
            ? Path.of(System.getProperty("user.home"), ".gradle")
            : Path.of(gradleHome);
        return base.toAbsolutePath().normalize().resolve("holin-hardening");
    }

    private static boolean prepareRepository(
        Path cacheHome,
        Path versionRoot,
        boolean offline,
        Map<String, String> environment
    ) throws Exception {
        Files.createDirectories(cacheHome.resolve("locks"));
        Path lockPath = cacheHome.resolve("locks/" + VERSION + ".lock");
        try (
            FileChannel channel = FileChannel.open(
                lockPath,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE
            );
            FileLock ignored = channel.lock()
        ) {
            if (validRepository(versionRoot)) return false;
            if (Files.exists(versionRoot)) quarantine(versionRoot, cacheHome.resolve("quarantine"));

            DownloadResult download = offline ? DownloadResult.none() : downloadRelease(cacheHome, environment);
            try {
                Path archive = download.archive();
                if (archive == null) archive = buildFromSource(offline, environment);
                require(archive != null && Files.isRegularFile(archive),
                    "portable repository is unavailable" + (offline ? " in offline mode" : ""));
                installArchive(archive, versionRoot, cacheHome);
                return download.interrupted();
            } catch (Exception failure) {
                if (download.interrupted()) Thread.currentThread().interrupt();
                throw failure;
            }
        }
    }

    private static DownloadResult downloadRelease(Path cacheHome, Map<String, String> environment) throws Exception {
        String url = firstNonBlank(environment.get("HARDENING_RELEASE_URL"), RELEASE_URL);
        return downloadRelease(cacheHome, URI.create(url), RELEASE_SHA256);
    }

    private static DownloadResult downloadRelease(Path cacheHome, URI url, String expectedChecksum) throws Exception {
        Path downloads = cacheHome.resolve("downloads");
        Files.createDirectories(downloads);
        Path temporary = Files.createTempFile(downloads, ARCHIVE_NAME + ".", ".tmp");
        boolean retainTemporary = false;
        try {
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20))
                .build();
            HttpRequest request = HttpRequest.newBuilder(url)
                .timeout(Duration.ofMinutes(3))
                .GET()
                .build();
            HttpResponse<Path> response = client.send(request, HttpResponse.BodyHandlers.ofFile(temporary));
            if (response.statusCode() < 200 || response.statusCode() >= 300) return DownloadResult.none();
            String actual = sha256(temporary);
            require(actual.equals(expectedChecksum),
                "portable Release checksum mismatch: expected=" + expectedChecksum + ", actual=" + actual);
            retainTemporary = true;
            return new DownloadResult(temporary, false);
        } catch (IllegalArgumentException | IOException failure) {
            return DownloadResult.none();
        } catch (InterruptedException failure) {
            return new DownloadResult(null, true);
        } finally {
            if (!retainTemporary) Files.deleteIfExists(temporary);
        }
    }

    private static Path buildFromSource(boolean offline, Map<String, String> environment) throws Exception {
        Path source = sourceDirectory(environment);
        if (source == null) return null;
        Path wrapper = source.resolve(isWindows() ? "gradlew.bat" : "gradlew");
        if (!Files.isRegularFile(wrapper) || !Files.isRegularFile(source.resolve("build.gradle.kts"))) return null;
        List<String> command = new ArrayList<>();
        command.add(wrapper.toString());
        command.add("--no-daemon");
        if (offline) command.add("--offline");
        command.add("packagePortableHardeningPlugin");
        Process process = new ProcessBuilder(command)
            .directory(source.toFile())
            .inheritIO()
            .start();
        int exitCode = process.waitFor();
        require(exitCode == 0, "portable repository source build failed with exit " + exitCode);
        Path archive = source.resolve("build/distributions/" + ARCHIVE_NAME);
        require(Files.isRegularFile(archive), "source build did not create " + archive);
        return archive;
    }

    private static Path sourceDirectory(Map<String, String> environment) {
        String explicit = environment.get("HARDENING_PLUGIN_SOURCE_DIR");
        if (explicit != null && !explicit.isBlank()) {
            Path path = Path.of(explicit).toAbsolutePath().normalize();
            return Files.isDirectory(path) ? path : null;
        }
        String property = System.getProperty("hardening.launcher.source");
        if (property != null && !property.isBlank()) {
            Path path = Path.of(property).toAbsolutePath().normalize();
            if (Files.isDirectory(path)) return path;
        }
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        return Files.isRegularFile(current.resolve("build.gradle.kts")) ? current : null;
    }

    private static void installArchive(Path archive, Path versionRoot, Path cacheHome) throws Exception {
        Path staging = Files.createTempDirectory(cacheHome, "install-" + VERSION + "-");
        try {
            unzip(archive, staging);
            require(validRepository(staging), "portable repository archive failed internal checksum validation");
            Files.createDirectories(versionRoot.getParent());
            publishAtomically(staging, versionRoot);
        } finally {
            deleteTree(staging);
            if (archive.startsWith(cacheHome.resolve("downloads"))) Files.deleteIfExists(archive);
        }
    }

    private static boolean validRepository(Path root) {
        Path checksumFile = root.resolve("SHA256SUMS");
        Path marker = root.resolve(MARKER);
        if (!Files.isRegularFile(checksumFile) || !Files.isRegularFile(marker)) return false;
        try {
            List<String> lines = Files.readAllLines(checksumFile, StandardCharsets.UTF_8);
            boolean markerCovered = false;
            Set<Path> files = new HashSet<>();
            for (String line : lines) {
                if (line.isBlank()) continue;
                Matcher matcher = CHECKSUM_LINE.matcher(line);
                if (!matcher.matches()) return false;
                String relative = matcher.group(2);
                Path file = safeArchivePath(root, relative);
                if (!files.add(file)) return false;
                if (!Files.isRegularFile(file)) return false;
                if (!sha256(file).equals(matcher.group(1))) return false;
                if (relative.equals(MARKER)) markerCovered = true;
            }
            return markerCovered;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static void unzip(Path archive, Path destination) throws IOException {
        Path normalizedRoot = destination.toAbsolutePath().normalize();
        Set<String> names = new HashSet<>();
        Set<Path> outputs = new HashSet<>();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(archive))) {
            while (true) {
                ZipEntry entry = zip.getNextEntry();
                if (entry == null) break;
                require(names.add(entry.getName()), "portable archive contains duplicate entry " + entry.getName());
                Path output = safeArchivePath(normalizedRoot, entry.getName());
                require(outputs.add(output), "portable archive contains duplicate entry " + entry.getName());
                if (entry.isDirectory()) {
                    Files.createDirectories(output);
                } else {
                    Files.createDirectories(output.getParent());
                    Files.copy(zip, output, StandardCopyOption.REPLACE_EXISTING);
                }
                zip.closeEntry();
            }
        }
    }

    private static int runConsumer(ParsedArguments parsed, Path repository, Map<String, String> environment)
        throws Exception {
        Path wrapper = parsed.projectDirectory().resolve(isWindows() ? "gradlew.bat" : "gradlew");
        List<String> command = new ArrayList<>();
        command.add(wrapper.toString());
        command.add("-PhardeningPluginRepo=" + repository.toAbsolutePath().normalize());
        command.addAll(parsed.forwarded());
        ProcessBuilder builder = new ProcessBuilder(command)
            .directory(parsed.projectDirectory().toFile())
            .inheritIO();
        builder.environment().putAll(environment);
        return builder.start().waitFor();
    }

    private static void quarantine(Path invalid, Path quarantineRoot) throws IOException {
        Files.createDirectories(quarantineRoot);
        Path target = quarantineRoot.resolve(VERSION + "-" + System.currentTimeMillis());
        move(invalid, target);
    }

    private static void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, target);
        }
    }

    private static void publishAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException failure) {
            throw new LauncherFailure("portable repository cache cannot be published atomically: " + failure.getMessage());
        }
    }

    private static Path safeArchivePath(Path root, String name) {
        require(!name.isBlank() && !name.startsWith("/") && !name.startsWith("\\"),
            "portable archive contains unsafe entry " + name);
        require(!name.contains("\\\\"), "portable archive contains unsafe entry " + name);
        Path relative = Path.of(name);
        require(!relative.isAbsolute() && relative.getNameCount() > 0,
            "portable archive contains unsafe entry " + name);
        for (Path component : relative) {
            require(!component.toString().equals(".") && !component.toString().equals(".."),
                "portable archive contains unsafe entry " + name);
        }
        Path output = root.resolve(relative).normalize();
        require(output.startsWith(root) && !output.equals(root), "portable archive contains unsafe entry " + name);
        return output;
    }

    private static void deleteTree(Path root) throws IOException {
        if (Files.notExists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            while (true) {
                int count = input.read(buffer);
                if (count < 0) break;
                digest.update(buffer, 0, count);
            }
        }
        StringBuilder value = new StringBuilder();
        for (byte item : digest.digest()) value.append(String.format("%02x", item));
        return value.toString();
    }

    private static int compareVersions(String actual, String minimum) {
        String[] left = actual.split("\\.");
        String[] right = minimum.split("\\.");
        int size = Math.max(left.length, right.length);
        for (int index = 0; index < size; index++) {
            int first = index < left.length ? Integer.parseInt(left[index]) : 0;
            int second = index < right.length ? Integer.parseInt(right[index]) : 0;
            if (first != second) return Integer.compare(first, second);
        }
        return 0;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) return first;
        return second != null && !second.isBlank() ? second : null;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new LauncherFailure(message);
    }

    private record ParsedArguments(Path projectDirectory, List<String> forwarded, boolean offline) {
        static ParsedArguments parse(List<String> arguments) {
            int separator = arguments.indexOf("--");
            require(separator >= 0, "usage: hardeningw --project-dir <path> -- <Gradle arguments>");
            List<String> launcher = arguments.subList(0, separator);
            List<String> forwarded = List.copyOf(arguments.subList(separator + 1, arguments.size()));
            require(forwarded.size() > 0, "at least one Gradle argument or task is required");
            require(launcher.size() == 2 && launcher.get(0).equals("--project-dir"),
                "usage: hardeningw --project-dir <path> -- <Gradle arguments>");
            Path project = Path.of(launcher.get(1)).toAbsolutePath().normalize();
            return new ParsedArguments(project, forwarded, forwarded.contains("--offline"));
        }
    }

    private record DownloadResult(Path archive, boolean interrupted) {
        static DownloadResult none() {
            return new DownloadResult(null, false);
        }
    }

    private static final class LauncherFailure extends RuntimeException {
        LauncherFailure(String message) {
            super(message);
        }
    }
}
