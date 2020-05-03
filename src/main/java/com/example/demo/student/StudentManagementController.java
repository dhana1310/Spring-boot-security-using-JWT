package com.example.demo.student;

import com.example.demo.model.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
      new Student(1, "James Bond"),
      new Student(2, "Maria Jones"),
      new Student(3, "Anna Smith")
    );

    @GetMapping
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINER')")
    public List<Student> getAllStudent() {
        return STUDENTS;
    }

    @PostMapping
//    @PreAuthorize("hasAuthority('STUDENT_WRITE')") //method level authorization using spring security
    public Student registerStudent(@RequestBody Student student) {
        System.out.println(student);
        return student;
    }

    @PutMapping
//    @PreAuthorize("hasAuthority('STUDENT_WRITE')")
    public Student updateStudent(@RequestBody Student student) {
        System.out.println(student);
        return student;
    }

    @DeleteMapping(path = "{studentId}")
//    @PreAuthorize("hasAuthority('STUDENT_WRITE')")
    public String deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println(studentId);
        return "SuccessFully Deleted";
    }
}
