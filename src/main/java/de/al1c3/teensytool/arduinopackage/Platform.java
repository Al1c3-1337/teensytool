package de.al1c3.teensytool.arduinopackage;

import java.util.List;

public class Platform {
    public String name;
    public String architecture;
    public String version;
    public String category;
    public Help help;
    public String url;
    public String archiveFileName;
    public String checksum;
    public String size;

    public List<Board> boards;
    public List<ToolsDependency> toolsDependencies;
    public List<DiscoveryDependency> discoveryDependencies;
    public List<MonitorDependency> monitorDependencies;
}
