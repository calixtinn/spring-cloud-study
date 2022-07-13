package calixto.study.course.service;

import calixto.study.course.model.Course;
import calixto.study.course.service.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CourseService {

    private final CourseRepository repository;

    public Iterable<Course> list(Pageable pageable) {
        log.info("Listing all courses");
        return repository.findAll(pageable);
    }
}
