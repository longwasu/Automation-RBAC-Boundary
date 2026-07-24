import rich
from rich.table import Table
from rbac_matrix import ProbeResult
from typing import List, Dict, Optional, Any
import xml.etree.ElementTree as ET

def render_table(results: List[ProbeResult]):
    if not results:
        print("[*] Không có dữ liệu để hiển thị.")
        return

    console = rich.get_console()
    table = Table(title="MA TRẬN KẾT QUẢ KIỂM TRA PHÂN QUYỀN",
                    title_style="bold magenta", show_lines=True)
    table.add_column("USER/GROUP")

    # Lọc trùng lặp -> danh sách -> sắp xếp
    groups = sorted(list(set(r.group for r in results)))
    users = sorted(list(set(r.username for r in results)))

    for group in groups:
        table.add_column(group, justify="center")

    for user in users:
        row_data = [user]
        for group in groups:
            cell_results = [r for r in results if r.username == user and r.group == group]
            print(f"[*] Kết quả cho user '{user}' và group '{group}': {cell_results}")

            if not cell_results:
                row_data.append("-")
            elif any(r.invariant_verdict for r in cell_results):
                row_data.append("[yellow]![/yellow]")
            elif all(r.ok for r in cell_results):
                row_data.append("[bold green]✓[/bold green]")
            else:
                row_data.append("[bold red]✗[/bold red]")

        table.add_row(*row_data)

    console.print(table)
    console.print(
    "\n[italic]Chú thích: "
    "[bold green]✓[/bold green] Trùng khớp Matrix | "
    "[bold red]✗[/bold red] Sai quyền | "
    "[bold yellow]![/bold yellow] Vi phạm luật cấm[/italic]\n"
    )


def write_junit(results: List[ProbeResult], path: str):
    """
    Xuất kết quả kiểm thử ra định dạng JUnit XML cho CI/CD.
    """
    if not results:
        print("[*] Không có dữ liệu để xuất ra JUnit XML.")
        return

    total_tests = len(results)
    total_failures = len([r for r in results if not r.ok])

    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(
        testsuites, 
        "testsuite", 
        name="RBAC Matrix Tests", 
        tests=str(total_tests), 
        failures=str(total_failures)
    )

    for r in results:
        classname = r.group
        testname = f"{r.username} {r.method} {r.path}"
        testcase = ET.SubElement(testsuite, "testcase", classname=classname, name=testname)

        if not r.ok:
            if r.invariant_verdict:
                ET.SubElement(testcase, "failure", )
    

    tree = ET.ElementTree(testsuites)
    if hasattr(ET, "indent"):
        ET.indent(tree, space="    ",)
    with open(path, "wb") as f:
        tree.write(f, encoding="utf-8", xml_declaration=True)


def render_error_details(results: List[ProbeResult]):
    # Lọc ra những case bị fail
    failed_results = [r for r in results if not r.ok]
    console = rich.get_console()
    # Nếu không có lỗi nào thì bỏ qua, không in gì cả
    if not failed_results:
        return

    console.print("\n[bold red]⚠️ CHI TIẾT CÁC TRƯỜNG HỢP KIỂM THỬ THẤT BẠI:[/bold red]")
    
    # Tạo một bảng mới chuyên để log lỗi
    error_table = Table(show_header=True, header_style="bold red", show_lines=True)
    error_table.add_column("User", justify="center")
    error_table.add_column("Group", justify="center")
    error_table.add_column("API Endpoint")
    error_table.add_column("Nguyên nhân Fail")

    for r in failed_results:
        # Phân tích nguyên nhân lỗi dựa vào các thuộc tính của ProbeResult
        if r.invariant_verdict:
            # Lỗi do vi phạm luật bất biến (Oracle)
            reason = f"[yellow]Vi phạm luật bất biến:[/yellow]\n{r.invariant_verdict}"
        elif r.actual_allow != r.matrix_expected:
            # Lỗi do hệ thống hoạt động không đúng với ma trận cấu hình
            reason = (
                f"[magenta]Lệch ma trận cấu hình![/magenta]\n"
                f"- Mong đợi (Matrix): {'[green]Cho phép[/green]' if r.matrix_expected else '[red]Chặn[/red]'}\n"
                f"- Thực tế (Hệ thống): {'[green]Cho phép[/green]' if r.actual_allow else '[red]Chặn[/red]'} "
                f"(Status: {r.status})"
            )
        else:
            reason = "Lỗi không xác định"

        # Hiển thị Path kèm theo HTTP Method
        api_info = f"[cyan]{r.method}[/cyan] {r.path}"
        
        error_table.add_row(r.username, r.group, api_info, reason)
        
    console.print(error_table)




    