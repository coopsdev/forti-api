# **Forti-API**

## **Streamlined API Access for FortiGate**

Welcome to Forti-API, an open-source project crafted to simplify and enhance your interaction with FortiGate's powerful APIs. Designed with network security professionals in mind, Forti-API transforms complex API tasks into streamlined operations, empowering you to unlock the full potential of your FortiGate systems.

## 🌟 **Early Access** 🌟

Get started with **Forti-API** effortlessly using Conan for dependency management. Whether you're using **Meson** or **CMake**, integrating Forti-API into your project is straightforward!

### 📦 **Add the Forti-API Remote**

First, add the Forti-API remote to your Conan configuration:

```bash
conan remote add forti-api https://repo.cooperhlarson.com/artifactory/api/conan/fortigate
```

### **Add the Dependency to Conan**

There are several ways to do this

**conanfile.py**: The more modern way with v2+ syntax

```python
class Pkg(ConanFile):
  name = "my_project"
  requires = ['forti-api/0.1.11']  # This is option 1

  def requirements(self):
    self.requires('forti-api/0.1.11')  # This is option 2, do not define requirements twice
    self.test_requires('gtest/1.14.0')  # 'test-requires' support makes this a best practice
```

**conanfile.txt**: while simpler, conanfile.py is preferred for more extensability

```bash
[requires]
forti-api/0.1.11
```

### 🚀 **Build System Integration**
Integrates Easily with Meson or CMake

**Meson**

```meson
forti_api_dep = dependency('forti-api', required: true)
```

**CMake**

```cmake
# Add Forti-API as a dependency
find_package(forti-api REQUIRED)

# Link Forti-API to your target
target_link_libraries(your_project_name PRIVATE forti-api::forti-api)
```

**Include**
```
#include <forti_api.hpp>  # universal import
#include <forti_api/*.hpp>  [api, threat_feed, dns_filter, system, firewall] + more planned in near future
```

### 🛠️ **Including Headers**
After setting up the dependency, you can include the necessary headers in your source files:

```cpp
#include <forti_api.hpp>          // Universal import for all API components
#include <forti_api/api.hpp>      // Specific imports for individual components
#include <forti_api/threat_feed.hpp>
#include <forti_api/dns_filter.hpp>
#include <forti_api/system.hpp>
#include <forti_api/firewall.hpp>
// ... more modules coming soon!
```


## Project Vision


### Simplifying FortiGate Management

**forti-api** is designed to turn the intricate world of FortiGate firewall management into something straightforward and accessible. By providing a clean interface that integrates seamlessly with your existing setup, this tool simplifies complex configurations, making advanced network management more approachable for everyone.

### Real-World Impact

With tools like **forti-hole** and **forti2ban**, **forti-api** integrates Pi-hole and Fail2Ban directly into the FortiGate ecosystem. These integrations have been proven to significantly enhance network security, achieving a 97% block-rate against ad traffic with the advanced DNS filter—transforming ad-heavy sites into cleaner, faster-loading pages, and reducing unnecessary network traffic by up to 20%.


## Engagement and Contributions


### Open to Collaboration

**forti-api** is a community-driven project, but contributing comes with important responsibilities:

- **Physical Device or FortiVM Requirement**: Contributors must own either a physical FortiGate device or a FortiVM subscription. FortiVM users, given the significant investment (approximately 10 times the cost of a 1-year UTM subscription on a physical FortiGate or the initial base price of hardware), are highly valued. If you're a FortiVM user, consider this your red carpet invitation—you're a big fish in a small market.

- **Rigorous Pull Request Process**: All pull requests will undergo thorough scrutiny. Whether you’re testing on a physical device or a FortiVM, your contributions will be subject to rigorous code reviews. Tests will be meticulously vetted for any potential harm before they reach my personal testing environment, ensuring that no changes will compromise the integrity of users' FortiGate setups.

- **Prioritizing Software Integrity**: Even though this is an open-source project, the integrity of the software is paramount. Every stage of development prioritizes security, understanding the immense trust involved in granting API access to a security device with super admin privileges.

- **Commitment to Transparency and Trust**: The open-source nature of **forti-api** allows the code to be audited by the community, which is crucial for maintaining security integrity. I am deeply committed to upholding this trust by adhering to the highest standards of software integrity.

This ensures that whether you're a FortiVM subscriber or a physical device owner, you understand the importance of your role in contributing to **forti-api** and the shared commitment to maintaining a robust and secure codebase.


---

**forti-api** is part of a broader effort to create reliable, efficient tools for network security management. Your participation can help shape the future of FortiGate management, making it more accessible and effective for everyone.

Join the community and help us simplify and enhance the FortiGate experience while upholding the highest standards of security and integrity.
